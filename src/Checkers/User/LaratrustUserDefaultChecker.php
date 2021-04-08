<?php

namespace Laratrust\Checkers\User;

use Illuminate\Support\Collection;
use Illuminate\Support\Str;
use Laratrust\Helper;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;

class LaratrustUserDefaultChecker extends LaratrustUserChecker
{
    /**
     * Checks if the user has a role by its name.
     *
     * @param  string|bool   $team      Team name.
     * @return array
     */
    public function getCurrentUserRoles($team = null)
    {
        /** @var Collection $roles */
        $roles = collect($this->userCachedRoles());

        if (config('laratrust.use_teams') === false) {
            return $roles->pluck->getKeyAttributeValue()->toArray();
        }

        if ($team === null && config('laratrust.teams_strict_check') === false) {
            return $roles->pluck(Helper::getRoleKeyAttributeName())->toArray();
        }

        if ($team === null) {
            return $roles->filter(function ($role) {
                return $role['pivot'][config('laratrust.foreign_keys.team')] === null;
            })->pluck(Helper::getRoleKeyAttributeName())->toArray();
        }

        $teamId = Helper::fetchTeam($team);

        return $roles->filter(function ($role) use ($teamId) {
            return $role['pivot'][config('laratrust.foreign_keys.team')] == $teamId;
        })->pluck(Helper::getRoleKeyAttributeName())->toArray();
    }

    /**
     * Checks if the user has a role by its name.
     *
     * @param  string|array  $name       Role name or array of role names.
     * @param  string|bool|array|null   $teams      Team name or requiredAll roles.
     * @param  bool          $requireAll All roles in the array are required.
     * @return bool
     */
    public function currentUserHasRole($name, $teams = null, $requireAll = false)
    {
        $name = Helper::standardize($name);
        [$teams, $requireAll] = Helper::assignRealValuesTo($teams, $requireAll, 'is_bool');

        if (is_array($name)) {
            if (empty($name)) {
                return true;
            }

            foreach ($name as $roleName) {
                $hasRole = $this->currentUserHasRole($roleName, $teams);

                if ($hasRole && !$requireAll) {
                    return true;
                } elseif (!$hasRole && $requireAll) {
                    return false;
                }
            }

            // If we've made it this far and $requireAll is FALSE, then NONE of the roles were found.
            // If we've made it this far and $requireAll is TRUE, then ALL of the roles were found.
            // Return the value of $requireAll.
            return $requireAll;
        }

        $teams = Helper::fetchTeams($teams);
        $attrName = Helper::getRoleKeyAttributeName();
        foreach ($this->userCachedRoles() as $role) {
            if ($role[$attrName] === $name && Helper::isInSameTeam($role, $teams)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user has a permission by its name.
     *
     * @param string|array           $permission Permission string or array of permissions.
     * @param string|bool|array|null $team       Team name or requiredAll roles.
     * @param bool                   $requireAll All roles in the array are required.
     *
     * @return bool
     */
    public function currentUserHasPermission($permission, $teams = null, $requireAll = false)
    {
        $permission = Helper::standardize($permission);
        [$teams, $requireAll] = Helper::assignRealValuesTo($teams, $requireAll, 'is_bool');

        if (is_array($permission)) {
            if (empty($permission)) {
                return true;
            }

            foreach ($permission as $permissionName) {
                $hasPermission = $this->currentUserHasPermission($permissionName, $teams);

                if ($hasPermission && !$requireAll) {
                    return true;
                }
                if (!$hasPermission && $requireAll) {
                    return false;
                }
            }

            // If we've made it this far and $requireAll is FALSE, then NONE of the perms were found.
            // If we've made it this far and $requireAll is TRUE, then ALL of the perms were found.
            // Return the value of $requireAll.
            return $requireAll;
        }

        $teams = Helper::fetchTeams($teams);
        $attrName = Helper::getPermissionKeyAttributeName();

        foreach ($this->userCachedPermissions() as $perm) {
            if (Helper::isInSameTeam($perm, $teams) && Str::is($permission, $perm[$attrName])) {
                return true;
            }
        }

        foreach ($this->userCachedRoles() as $role) {
            $role = Helper::hidrateModel(Config::get('laratrust.models.role'), $role);

            if (Helper::isInSameTeam($role, $teams) && $role->hasPermission($permission)) {
                return true;
            }
        }

        return false;
    }

    public function currentUserFlushCache()
    {
        Cache::forget('laratrust_roles_for_'.$this->userModelCacheKey() .'_'. $this->user->getKey());
        Cache::forget('laratrust_permissions_for_'.$this->userModelCacheKey() .'_'. $this->user->getKey());
    }

    /**
     * Tries to return all the cached roles of the user.
     * If it can't bring the roles from the cache,
     * it brings them back from the DB.
     *
     * @param \Illuminate\Database\Eloquent\Model $model
     * @return \Illuminate\Database\Eloquent\Collection
     */
    protected function userCachedRoles()
    {
        $cacheKey = 'laratrust_roles_for_'.$this->userModelCacheKey() .'_'. $this->user->getKey();

        if (!Config::get('laratrust.cache.enabled')) {
            return $this->user->roles()->get();
        }

        return Cache::remember($cacheKey, Config::get('laratrust.cache.expiration_time', 60), function () {
            return $this->user->roles()->get()->toArray();
        });
    }

    /**
     * Tries to return all the cached permissions of the user
     * and if it can't bring the permissions from the cache,
     * it brings them back from the DB.
     *
     * @return \Illuminate\Database\Eloquent\Collection
     */
    public function userCachedPermissions()
    {
        $cacheKey = 'laratrust_permissions_for_'.$this->userModelCacheKey() .'_'. $this->user->getKey();

        if (!Config::get('laratrust.cache.enabled')) {
            return $this->user->permissions()->get();
        }

        return Cache::remember($cacheKey, Config::get('laratrust.cache.expiration_time', 60), function () {
            return $this->user->permissions()->get()->toArray();
        });
    }

    /**
     * Tries return key name for user_models
     *
     * @return string default key user
     */
    public function userModelCacheKey()
    {
        if (!Config::get('laratrust.use_morph_map')) {
            return 'user';
        }

        foreach (Config::get('laratrust.user_models') as $key => $model) {
            if ($this->user instanceof $model) {
                return $key;
            }
        }
    }
}
