<?php

namespace Laratrust\Models;

/**
 * This file is part of Laratrust,
 * a role & permission management solution for Laravel.
 *
 * @license MIT
 * @package Laratrust
 */
use Illuminate\Support\Facades\Config;
use Illuminate\Database\Eloquent\Model;
use Laratrust\Traits\LaratrustKeyable;
use Laratrust\Traits\LaratrustTeamTrait;
use Laratrust\Contracts\LaratrustTeamInterface;

class LaratrustTeam extends Model implements LaratrustTeamInterface
{
    use LaratrustTeamTrait;
    use LaratrustKeyable;

    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table;

    /**
     * Creates a new instance of the model.
     *
     * @param  array  $attributes
     * @return void
     */
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);
        $this->table = Config::get('laratrust.tables.teams');
    }
}
