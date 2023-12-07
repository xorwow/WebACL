# WebACL Filesystem/ACL Interface

# Requires a linux system because of the grp import

import config
import logging, subprocess, os, grp
from threading import RLock

# Important actions are logged in parseable format in an extra log file (permissions modifications)
alog = logging.FileHandler('actions.log', 'a', 'utf-8')
alog.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d-%H-%M-%S"))
alog.setLevel(logging.INFO)

log = logging.getLogger(__name__)
log.setLevel(config.MIN_LOG_LEVEL)

action_log = logging.getLogger('actions')
action_log.addHandler(alog)

## ENTITY MANAGEMENT

entity_cache_lock = RLock()
entity_cache = {}

def clear_entity_cache():
    global entity_cache, entity_cache_lock
    with entity_cache_lock:
        log.debug(f"Clearing entity cache ({ len(entity_cache) } elements)")
        entity_cache = {}

def get_entity(name, check_name=True, is_group=None):
    global entity_cache, entity_cache_lock
    # If not disabled, check if name is legal and exists (for command injection protection)
    # A legal name only contains letters, numbers and ._-
    if check_name:
        if not (name and str(name).replace('.', '').replace('_', '').replace('-', '').isalnum()):
            log.warn(f"Illegal entity name detected when asked to prepare entity data: { name }")
            return None
    # Check if entity exists and fetch entity type (group/user) if not disabled/given
    if check_name or is_group == None:
        try:
                data = grp.getgrnam(name)
                is_group = not data[3]
        except KeyError:
            log.warn(f"Non-existent entity detected when asked to prepare entity data: { name }")
            return None
    # Check for entity in cache
    with entity_cache_lock:
        if name in entity_cache:
            return entity_cache[name]
        # If not in cache, create entity and add to cache
        entity = Group(name) if is_group else User(name)
        entity_cache[name] = entity
        return entity

class Entity():

    def __init__(self, entity_name, is_group, is_admin):
        self.name = entity_name
        self.is_group = is_group
        self.is_admin = is_admin
        self.is_protected = entity_name in config.PROTECTED_GROUPS + config.PROTECTED_USERS

    # Group may be Group() object or group name
    def in_group(self, group):
        return self == group

    def __eq__(self, other):
        return self.name == (other.name if issubclass(type(other), Entity) else other)
    
    def __str__(self):
        return f"{ 'Group' if self.is_group else 'User' } { self.name }{ ' (Admin)' if self.is_admin else '' }"

class User(Entity):

    def __init__(self, username):
        super().__init__(username, False, False)
        self.groups = self._groups()
        # Override "False" after groups have been fetched
        self.is_admin = any (self.in_group(admin_group) for admin_group in config.ADMIN_GROUPS + config.ADMIN_USERS)
        self.login_allowed = self.is_admin or any (self.in_group(login_group) for login_group in config.ALLOWED_LOGIN_GROUPS)

    # Overrides super method
    def in_group(self, group):
        return group in self.groups
    
    # Internal method for fetching user groups
    # Will ususally be called once and then fetched from cache
    def _groups(self):
        try:
            output = subprocess.check_output(['groups', self.name], encoding='utf8', stderr=subprocess.DEVNULL)
            groups = output.split()
            if ':' in groups:
                groups.remove(':')
            return groups
        except Exception as e:
            if type(e) is not subprocess.CalledProcessError:
                log.error(f"Could not fetch user groups for '{ self.name }'")
                log.exception(e)
            else:
                log.warn(f"Could not fetch user groups for '{ self.name }', probably user non-existent")
            return []

class Group(Entity):

    def __init__(self, group_name):
        super().__init__(group_name, True, group_name in config.ADMIN_GROUPS)

## FOLDER MANAGEMENT

# Special cache for admin view: Cache all visible folders for a user to be able to remove them afterwards
visible_folders_cache_lock = RLock()
visible_folders_cache = {}

# Remove a whole result collection of folders from the cache
def remove_result_from_visible_folders_cache(user):
    global visible_folders_cache, visible_folders_cache_lock
    with visible_folders_cache_lock:
        visible_folders_cache.pop(user.name, None)

# Remove a single folder (by it's relative path) from a cached result
def remove_path_from_visible_folders_result(user, relpath):
    global visible_folders_cache, visible_folders_cache_lock
    with visible_folders_cache_lock:
        if user.name not in visible_folders_cache:
            return
        path = relpath.split(os.path.sep)
        curr_list = visible_folders_cache[user.name]
        while curr_list and path:
            for subfolder in curr_list:
                if subfolder[0].name == path[0]:
                    path.pop(0)
                    if not path:
                        curr_list.remove(subfolder)
                        return
                    curr_list = subfolder[1]
                    break
            else:
                return

# Get all folders visible to a user (includes readonly)
# Searches up to config.MAX_SEARCH_DEPTH
# Format: [ ( folder1, [ ( subfolder1, [ ... ] ), ... ] ), ... ]
def visible_folders(user):
    global visible_folders_cache, visible_folders_cache_lock
    log.debug(f"Calculating visible folders for user: { user.name }")
    with visible_folders_cache_lock:
        if user.name in visible_folders_cache:
            return visible_folders_cache[user.name]
    root_folder = get_folder(config.BASE_REALPATH, name='ROOT', check_path=False)
    result = _recurse_visible_folders(user, root_folder, _depth=config.MAX_SEARCH_DEPTH)
    with visible_folders_cache_lock:
        visible_folders_cache[user.name] = result
    return result

def _recurse_visible_folders(user, curr_folder, _depth=0):
    subfolders = []
    if _depth == 0:
        return subfolders
    _depth -= 1
    for subfolder in curr_folder.subfolders():
        if subfolder.has_access(user, allow_readonly=True):
            folder_tuple = (subfolder, _recurse_visible_folders(user, subfolder, _depth=_depth))
            subfolders.append(folder_tuple)
    return subfolders

# Remove a user from all folders visible to them, return success bool
def remove_all_folder_permissions(user):
    log.debug(f"Removing all visible folders for user: { user.name }")
    folders = visible_folders(user)
    remove_result_from_visible_folders_cache(user)
    permissions = [ Permission(user, True), Permission(user, False) ]
    return _recursive_remove(permissions, folders)

def _recursive_remove(permissions, folders):
    success = True
    for folder in folders:
        for permission in permissions:
            success &= folder[0].remove_permission(permission, ignore_protection=True)
        success &= _recursive_remove(permissions, folder[1])
    return success

folder_cache_lock = RLock()
folder_cache = {}

def clear_folder_cache():
    global folder_cache, folder_cache_lock
    with folder_cache_lock:
        log.debug(f"Clearing folder cache ({ len(folder_cache) } elements)")
        folder_cache = {}

# Get a folder object from cache or create one
# Returns None if the path is invalid
def get_folder(path, name=None, check_path=True):
    global folder_cache, folder_cache_lock
    dir = path
    # If not disabled, extend path to absolute and check if legal
    if check_path:
        dir = _to_real_path(path)
        if not dir:
            return None
    # Check for folder in cache
    with folder_cache_lock:
        if dir in folder_cache:
            return folder_cache[dir]
        # If not in cache, create folder and add to cache
        folder = Folder(dir, folder_name=name)
        folder_cache[dir] = folder
        return folder

# Converts directory path to absolute path and checks if within safe bounds
# Returns RETURN_CODES.{PATH_NOT_FOUND,PATH_OUTSIDE_BOUNDS} on error, else abs. path
def _to_real_path(path):
    # Create absolute path if not already absolute
    dir = os.path.join(os.path.realpath(path), '')
    if not os.path.commonprefix([config.BASE_REALPATH, dir]) == config.BASE_REALPATH:
        dir = os.path.join(os.path.realpath(os.path.join(config.SAFE_BASE_PATH, path)), '')
    # Test if path within bounds
    if not os.path.commonprefix([config.BASE_REALPATH, dir]) == config.BASE_REALPATH:
        log.warn(f"Query for out-of-bounds directory access has been caught, directory was: { dir }")
        return None
    # Test if directory exists
    if not os.path.isdir(dir):
        log.warn(f"Query for non-existent directory access has been caught, directory was: { dir }")
        return None
    return dir

class Folder():

    def __init__(self, validated_realpath, folder_name=None):
        self.path = validated_realpath
        self.relpath = os.path.relpath(self.path, config.SAFE_BASE_PATH)
        if not folder_name:
            folder_name = os.path.basename(self.path)
        self.name = folder_name
        self._cached_permissions = None

    def subfolders(self):
        return [ get_folder(f.path, name=f.name, check_path=False) for f in os.scandir(self.path) if f.is_dir() ]
    
    def has_access(self, entity, allow_readonly=False):
        if entity.is_admin:
            return True
        for permission in self.permissions():
            if not allow_readonly and permission.readonly:
                continue
            if entity.in_group(permission.entity):
                return True
        return False
    
    def permissions(self, return_none_on_error=False):
        if self._cached_permissions:
            return self._cached_permissions
        perms = []
        try:
            # Parse `getfacl` command output lines
            output = subprocess.check_output(['getfacl', '-p', self.path], encoding='utf8').split('\n')
            for entry in output:
                # Check for `default` (inheritance) flag and remove if present
                inheritable = entry.startswith('default:')
                if inheritable:
                    entry = entry[8:]
                # For both users and groups: Check correct syntax and create respective entity
                for type in [ 'user:', 'group:' ]:
                    # Expected format: <user/group>:<id>:<rwx>
                    if entry.startswith(f"{ type }"):
                        entry = entry[len(type):]
                        parts = entry.split(':')
                        if not entry[0] == ':' and len(parts) == 2 and len(parts[1]) == 3:
                            entity = get_entity(parts[0], check_name=False, is_group=(type == 'group:'))
                            perms.append(Permission(entity, inheritable, readonly=(parts[1][1] != 'w')))
        except Exception as e:
            log.error(f"Failed to fetch folder permissions for { self.path }")
            log.exception(e)
            return None if return_none_on_error else []
        perms.sort(key=lambda x: str.casefold(x.entity.name))
        self._cached_permissions = perms
        return perms

    def remove_permission(self, permission, ignore_protection=False):
        name = permission.entity.name
        is_user = not permission.entity.is_group
        inheritable = permission.inheritable
        action_log.info(f"REMOVE ENTITY '{ name }'{ ' INHERITABLE' if inheritable else '' } FROM FOLDER: { self.path }")
        self._clear_permission_cache()
        try:
            if not ignore_protection and permission.entity.is_protected:
                raise Exception('Tried to remove a protected entity')
            if inheritable:
               os.system(f'setfacl -dx { "u" if is_user else "g" }:{ name } "{ self.path }"')
            else:
               os.system(f'setfacl -x { "u" if is_user else "g" }:{ name } "{ self.path }"')
        except Exception as e:
            log.error(f"Failed to remove { 'inheritable' if inheritable else '' } permission for { name } to { self.path }")
            log.exception(e)
            return False
        return True
    
    def add_permission(self, permission, ignore_protection=False):
        name = permission.entity.name
        is_user = not permission.entity.is_group
        inheritable = permission.inheritable
        readonly = permission.readonly
        action_log.info(f"ADD ENTITY '{ name }'{ ' INHERITABLE' if inheritable else '' } TO FOLDER: { self.path }")
        self._clear_permission_cache()
        try:
            if not ignore_protection and permission.entity.is_protected:
                raise Exception('Tried to add a protected entity')
            if inheritable:
               os.system(f'setfacl -dm { "u" if is_user else "g" }:{ name }:r{ "" if readonly else "w" }x "{ self.path }"')
            else:
               os.system(f'setfacl -m { "u" if is_user else "g" }:{ name }:r{ "" if readonly else "w" }x "{ self.path }"')
            # Add readonly permissions to all parent dirs to allow for folder traversion
            current_dir = self
            while current_dir.path != config.BASE_REALPATH:
                current_dir = get_folder(os.path.realpath(os.path.join(current_dir.path, os.pardir)))
                if not current_dir:
                    break
                if not current_dir.has_access(permission.entity, allow_readonly=True):
                    os.system(f'setfacl -m { "u" if is_user else "g" }:{ name }:rx "{ current_dir.path }"')
        except Exception as e:
            log.error(f"Failed to add { 'inheritable' if inheritable else '' } permission for { name } to { self.path }")
            log.exception(e)
            return False
        return True

    def _clear_permission_cache(self):
        self._cached_permissions = None

    def __str__(self):
        return f"Folder { self.path }"

class Permission():

    def __init__(self, entity, inheritable, readonly=False):
        self.entity = entity
        self.inheritable = inheritable
        self.readonly = readonly
