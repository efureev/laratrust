<?php

namespace Laratrust;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphPivot;
use Illuminate\Support\Facades\Config;
use InvalidArgumentException;
use Sitesoft\Alice\Modules\News\Models\News;

class Helper
{
    /**
     * Gets the it from an array, object or integer.
     *
     * @param  mixed  $object
     * @param  string  $type
     * @return int
     */
    public static function getIdFor($object, $type)
    {
        if ($object===null) {
            return null;
        }
        if (is_object($object)) {
            return $object->getKey();
        }
        if (is_array($object)) {
            return $object['id'];
        }
        if (is_numeric($object)) {
            return $object;
        }
        if (is_string($object)) {
            $cls = Config::get("laratrust.models.{$type}");
            return call_user_func_array([
                $cls, 'where'
            ], [$cls::getKeyAttributeName(), $object])->firstOrFail()->getKey();
        }

        throw new InvalidArgumentException(
            'getIdFor function only accepts an integer, a Model object or an array with an "id" key'
        );
    }

    /**
     * Check if a string is a valid relationship name.
     *
     * @param string $relationship
     * @return boolean
     */
    public static function isValidRelationship($relationship)
    {
        return in_array($relationship, ['roles', 'permissions']);
    }

    /**
     * Returns the team's foreign key.
     *
     * @return string
     */
    public static function teamForeignKey()
    {
        return Config::get('laratrust.foreign_keys.team');
    }

    /**
     * Fetch the team model from the name.
     *
     * @param  mixed  $team
     * @return mixed
     */
    public static function fetchTeam($team = null)
    {
        if (is_null($team) || !Config::get('laratrust.use_teams')) {
            return null;
        }

        return static::getIdFor($team, 'team');
    }

    /**
     * Fetch the team models from the name.
     *
     * @param  array  $team
     * @return array
     */
    public static function fetchTeams($teams)
    {
        return $teams ? static::getIdsFor((array) $teams, 'team') : null;
    }

    /**
     * Assing the real values to the team and requireAllOrOptions parameters.
     *
     * @param  mixed|array  $teams
     * @param  mixed  $requireAllOrOptions
     * @return array
     */
    public static function assignRealValuesTo($teams, $requireAllOrOptions, $method)
    {
        return [
            ($method($teams) ? null : $teams),
            ($method($teams) ? $teams : $requireAllOrOptions),
        ];
    }

    /**
     * Checks if the string passed contains a pipe '|' and explodes the string to an array.
     * @param  string|array  $value
     * @return string|array
     */
    public static function standardize($value, $toArray = false)
    {
        if (is_array($value) || ((strpos($value, '|') === false) && !$toArray)) {
            return $value;
        }

        return explode('|', $value);
    }

    /**
     * Check if a role or permission is attach to the user in a same team.
     *
     * @param  mixed  $rolePermission
     * @param  \Illuminate\Database\Eloquent\Model|array  $team
     * @return boolean
     */
    public static function isInSameTeam($rolePermission, $team)
    {
        if (
            !Config::get('laratrust.use_teams')
            || (!Config::get('laratrust.teams_strict_check') && is_null($team))
        ) {
            return true;
        }

        $teamForeignKey = static::teamForeignKey();

        return in_array($rolePermission['pivot'][$teamForeignKey], (array) $team);
    }

    /**
     * Checks if the option exists inside the array,
     * otherwise, it sets the first option inside the default values array.
     *
     * @param  string  $option
     * @param  array  $array
     * @param  array  $possibleValues
     * @return array
     */
    public static function checkOrSet($option, $array, $possibleValues)
    {
        if (!isset($array[$option])) {
            $array[$option] = $possibleValues[0];

            return $array;
        }

        $ignoredOptions = ['team', 'foreignKeyName'];

        if (!in_array($option, $ignoredOptions) && !in_array($array[$option], $possibleValues, true)) {
            throw new InvalidArgumentException();
        }

        return $array;
    }

    /**
     * Creates a model from an array filled with the class data.
     *
     * @param string $class
     * @param string|\Illuminate\Database\Eloquent\Model $data
     * @return \Illuminate\Database\Eloquent\Model
     */
    public static function hidrateModel($class, $data)
    {
        if ($data instanceof Model) {
            return $data;
        }

        if (!isset($data['pivot'])) {
            throw new \Exception("The 'pivot' attribute in the {$class} is hidden");
        }

        $model = new $class;
        $primaryKey = $model->getKeyName();

        $model->setAttribute($primaryKey, $data[$primaryKey])->setAttribute($class::getKeyAttributeName(), $data[$class::getKeyAttributeName()]);
        $model->setRelation(
            'pivot',
            MorphPivot::fromRawAttributes($model, $data['pivot'], 'pivot_table')
        );

        return $model;
    }

    /**
     * Return two arrays with the filtered permissions between the permissions
     * with wildcard and the permissions without it.
     *
     * @param array $permissions
     * @return array [$wildcard, $noWildcard]
     */
    public static function getPermissionWithAndWithoutWildcards($permissions)
    {
        $wildcard = [];
        $noWildcard = [];

        foreach ($permissions as $permission) {
            if (strpos($permission, '*') === false) {
                $noWildcard[] = $permission;
            } else {
                $wildcard[] = str_replace('*', '%', $permission);
            }
        }

        return [$wildcard, $noWildcard];
    }

    public static function getPermissionKeyAttributeName()
    {
        static $permissionKeyAttributeName;
        if ($permissionKeyAttributeName === null) {
            $permissionKeyAttributeName = Config::get('laratrust.models.permission')::getKeyAttributeName();
        }

        return $permissionKeyAttributeName;
    }

    public static function getRoleKeyAttributeName()
    {
        static $roleKeyAttributeName;
        if ($roleKeyAttributeName === null) {
            $roleKeyAttributeName = Config::get('laratrust.models.role')::getKeyAttributeName();
        }

        return $roleKeyAttributeName;
    }

    /**
     * Gets the it from an array, object or integer.
     *
     * @param  array  $objects
     * @param  string  $type
     * @return array
     */
    public static function getIdsFor(array $objects, $type)
    {
        $result = [];

        foreach ($objects as $object) {
            $result[] = self::getIdFor($object, $type);
        }

        return $result;
    }
}
