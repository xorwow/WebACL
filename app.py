# WebACL Flask Application (Linux only due to grp import in acl.py)

# External import(s): flask, flask_oidc2, pyopenssl, certifi

import config, fstools
import logging, sys
from markupsafe import escape
from flask import Flask, request, url_for, render_template, redirect, abort, flash
from flask_oidc import OpenIDConnect

app = Flask(__name__)
app.config.update(config.OIDC_CONFIG)

oidc = OpenIDConnect(app)

## Logging config

# Base single-session logger
logging.getLogger('werkzeug').setLevel(logging.ERROR)
logging.basicConfig(
    handlers = [ logging.FileHandler('session.log', 'w', 'utf-8') ],
    level = logging.INFO,
    format = '\n=== %(levelname)s %(asctime)s %(filename)s:%(lineno)s\nin %(module)s.%(funcName)s:\n%(message)s',
    datefmt = '%d.%m.%Y %H:%M:%S'
)

plog = logging.StreamHandler(sys.stdout)
plog.setFormatter(logging.Formatter("%(levelname)s (%(module)s) > %(message)s"))
plog.setLevel(config.MIN_LOG_LEVEL)
logging.getLogger('').addHandler(plog)

log = logging.getLogger(__name__)
log.setLevel(config.MIN_LOG_LEVEL)

## App

# Flask message flashing categories
INFO, GOOD, WARN, ERROR = 'info', 'good', 'warn', 'error'

# Fetches the currently logged in user's entity object or aborts the caller's connection on failure
def current_user():
    if not oidc.user_loggedin:
        log.warn('current_user called but user not logged in')
        abort(403)
    username = oidc.user_getfield('preferred_username')
    if not username:
        log.warn('User logged in but no username field provided')
        abort(403)
    user = fstools.get_entity(username)
    if not user or type(user) is not fstools.User:
        log.warn(f"User '{ username }' could not be resolved in the system")
        abort(403)
    if not user.login_allowed:
        log.warn(f"User '{ username }' tried to log in but is not a part of the allowed groups")
        abort(403)
    return user

@app.errorhandler(403)
def page_not_found(e):
    return render_template('403.html'), 403

@app.route('/logout/')
@oidc.require_login
def logout():
    oidc.logout()
    return "Sie wurden lokal ausgeloggt. Um nicht automatisch wieder eingeloggt zu werden, loggen Sie sich auch beim SSO aus."

@app.route('/')
def index():
    return redirect(url_for('folder_overview'))

@app.route("/folders/")
@oidc.require_login
# Display root subdirs and link to admin view if privileged
def folder_overview():
    user = current_user()
    log.debug(f"{ user }: Showing folder listing")
    subfolders = fstools.get_folder(config.BASE_REALPATH).subfolders()
    subfolders.sort(key=lambda x: str.casefold(x.name))
    return render_template('folder_overview.html', username=user.name, subfolders=subfolders, is_admin=user.is_admin)

# Update a folder's permisisons from view_folder POST data
def handle_folder_update(command, folder, is_privileged_request):
    log.info(f"POST data for folder update: { command }")
    # Check that required fields are present
    if all (field not in command for field in ('add', 'remove')):
        log.warn('Invalid POST data')
        abort(401)
    # Collect data from fields
    is_add = 'add' in command
    inheritable = command['inheritance'] == 'on' if 'inheritance' in command else False
    readonly = command['readonly'] == 'on' if 'readonly' in command else False
    entity_name = command['add'] if is_add else command['remove']
    entity = fstools.get_entity(entity_name)
    if not entity:
        log.warn(f"Entity for permission update could not be found: { entity_name }")
        flash('Username ist nicht gültig', ERROR)
        return
    if entity.is_protected and not is_privileged_request:
        log.warn('Caught attempt to update protected permission without admin rights')
        abort(401)
    permission = fstools.Permission(entity, inheritable, readonly=readonly)
    log.info(f"{ 'Adding' if is_add else 'Removing' }{ ' inheritable' if inheritable else '' }{ ' readonly' if readonly else '' } permission for { entity } to folder: { folder.path }")
    # Perform permission update
    if (folder.add_permission(permission) if is_add else folder.remove_permission(permission)):
        flash(f"Berechtigung { 'hinzugefügt' if is_add else 'entfernt' }", GOOD)
    else:
        log.warn(f"Failed to { 'add' if is_add else 'remove' } permission")
        flash(f"Berechtigung konnte nicht { 'hinzugefügt' if is_add else 'entfernt' } werden", ERROR)

@app.route("/folders/<path:subpath>", methods=['GET', 'POST'])
@oidc.require_login
# Update folder permissions on POST and display folder details
def view_folder(subpath):
    # Verify user and path
    user = current_user()
    log.debug(f"{ user }: Accessing folder details: { subpath }")
    folder = fstools.get_folder(subpath)
    if not folder or not folder.has_access(user):
        log.warn(f"Caught unauthorized access attempt or illegal folder: { subpath }")
        flash('Auf diesen Ordner kann nicht zugegriffen werden oder er existiert nicht', ERROR)
        return redirect(url_for('folder_overview'))
    # Handle folder update if request includes POST data
    if request.method == 'POST':
        data = request.form
        handle_folder_update(data, folder, user.is_admin)
    # Get non-protected permissions for folder and split into users and groups
    perms = [ perm for perm in folder.permissions(return_none_on_error=True) if not perm.entity.is_protected or user.is_admin ]
    if perms == None:
        log.error('Permissions could not be loaded')
        flash('Beim Laden der Berechtigungen ist ein Fehler aufgetreten', ERROR)
        return redirect(url_for('folder_overview'))
    users, groups = [], []
    [ (users if type(perm.entity) is fstools.User else groups).append(perm) for perm in perms ]
    # Render folder details
    subfolders = folder.subfolders()
    subfolders.sort(key=lambda x: str.casefold(x.name))
    return render_template('view_folder.html', curr_path=folder.relpath, subfolders=subfolders, users=users, groups=groups)

# Handle various admin commands from admin_view POST data
def handle_admin_request(command):
    log.info(f"POST data for admin request: { command }")
    target_user, folders = None, []
    # If a username from new or previous search results has been included, check it's validity
    if any (field in command for field in ('user', 'search')):
        username = command['user'] if 'user' in command else command['search']
        target_user = fstools.get_entity(username)
        if not target_user or type(target_user) is not fstools.User:
            log.warn(f"Username given, but non-existent or group: { username }")
            flash('Der angegebene Username ist ungültig', ERROR)
            return None, []
    # CASE 1: Cache clearing requested
    if 'cache' in command:
        log.debug(f"Performing cache clearing for { command['cache'] } cache")
        fstools.clear_folder_cache() if command['cache'] == 'folder' else fstools.clear_entity_cache()
        flash('Cache wurde geleert', GOOD)
    # CASE 2: Permission removal requested
    elif 'remove' in command:
        if not target_user:
            log.warn('Permission removal requested but no user given')
            abort(401)
        relpath = command['remove']
        # Remove ALL permissions for a user
        if relpath == 'REMOVE-ALL':
            log.debug(f"Removing all permissions for user: { target_user.name }")
            if fstools.remove_all_folder_permissions(target_user):
                flash('Alle direkten Berechtigungen wurden entfernt', GOOD)
            else:
                log.warn('Not all permissions could be removed')
                flash('Nicht alle Berechtigungen konnten entfernt werden', WARN)
        # Remove ONE permission for a user
        else:
            log.debug(f"Removing permission for user '{ target_user.name }' from folder: { relpath }")
            # Remove the folder from the cached result if present, so that the cache is still up-to-date (hopefully)
            fstools.remove_path_from_visible_folders_result(target_user, relpath)
            folder = fstools.get_folder(relpath)
            if not folder:
                log.warn(f"Could not remove permission for folder, invalid path: { relpath }")
                flash('Die Berechtigung konnte nicht entfernt werden, da der Ordner nicht gültig ist', ERROR)
            success = folder.remove_permission(fstools.Permission(target_user, True), ignore_protection=True)
            success &= folder.remove_permission(fstools.Permission(target_user, False), ignore_protection=True)
            if success:
                flash('Berechtigung erfolgreich entfernt', GOOD)
            else:
                log.warn('Permission could not be removed')
                flash('Berechtigung konnte nicht entfernt werden', ERROR)
    # CASE 3: Start a new search for a user's permissions
    elif 'search' in command:
        log.debug(f"Performing visible folder listing for user: { target_user.name }")
        # Remove previous search result for this user from the cache to provide up-to-date results
        fstools.remove_result_from_visible_folders_cache(target_user)
    # CASE ERROR: Command is neither cache clearing, permission removal nor user search
    else:
        log.warn('Invalid POST data')
        abort(401)
    # Prepare a user's visible folders if a user search has startet or is still in effect
    if target_user:
        folders = fstools.visible_folders(target_user)
    return target_user, folders

@app.route("/admin/", methods=['GET', 'POST'])
@oidc.require_login
# Manage caches and all permissions for a given user (this site is admin-only)
def admin_view():
    # Verify user and admin rights
    user = current_user()
    log.debug(f"{ user }: Accessing admin page")
    if not user.is_admin:
        log.warn('Caught attempt to load admin page without admin rights')
        flash('Sie verfügen nicht über die nötigen Berechtigungen für den Admin-Bereich', ERROR)
        return redirect(url_for('folder_overview'))
    # Prepare data and handle admin requests if applicable
    target_user, folders = None, []
    if request.method == 'POST':
        data = request.form
        target_user, folders = handle_admin_request(data)
    username = target_user.name if target_user else None
    # Render admin portal
    return render_template('admin_view.html', folders=folders, username=username)

if __name__ == '__main__':
      app.run(host='0.0.0.0', port=443)
