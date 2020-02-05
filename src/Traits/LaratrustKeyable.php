<?php

namespace Laratrust\Traits;

/**
 * This file is part of Laratrust,
 * a role & permission management solution for Laravel.
 *
 * @license MIT
 * @package Laratrust
 */
trait LaratrustKeyable
{
    /**
     * @return string
     */
    public static function getKeyAttributeName(): string
    {
        return 'name';
    }

    /**
     * @return mixed
     */
    public function getKeyAttributeValue()
    {
        return $this->{static::getKeyAttributeName()};
    }
}
