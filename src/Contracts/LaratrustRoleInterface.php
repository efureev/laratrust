<?php

namespace Laratrust\Contracts;

/**
 * This file is part of Laratrust,
 * a role & permission management solution for Laravel.
 *
 * @license MIT
 * @package Laratrust
 */
interface LaratrustRoleInterface
{
    /**
     * Key-column's name
     *
     * @return string
     */
    public static function getKeyAttributeName(): string;

    /**
     * Key-column's value
     *
     * @return mixed
     */
    public function getKeyAttributeValue();

    /**
     * Morph by Many relationship between the role and the one of the possible user models.
     *
     * @param  string  $relationship
     * @return \Illuminate\Database\Eloquent\Relations\MorphToMany
     */
    public function getMorphByUserRelation($relationship);

    /**
     * Many-to-Many relations with the permission model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function permissions();

    /**
     * Checks if the role has a permission by its name.
     *
     * @param  string|array  $permission       Permission name or array of permission names.
     * @param  bool  $requireAll       All permissions in the array are required.
     * @return bool
     */
    public function hasPermission($permission, $requireAll);

    /**
     * Save the inputted permissions.
     *
     * @param  mixed  $permissions
     * @return array
     */
    public function syncPermissions($permissions);

    /**
     * Attach permission to current role.
     *
     * @param  object|array  $permission
     * @return void
     */
    public function attachPermission($permission);

    /**
     * Detach permission from current role.
     *
     * @param  object|array  $permission
     * @return void
     */
    public function detachPermission($permission);

    /**
     * Attach multiple permissions to current role.
     *
     * @param  mixed  $permissions
     * @return void
     */
    public function attachPermissions($permissions);

    /**
     * Detach multiple permissions from current role
     *
     * @param  mixed  $permissions
     * @return void
     */
    public function detachPermissions($permissions);
}
