<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;
use App\Models\User;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        $users = User::factory()
            ->count(100)
            ->make();

        $chunks = $users->chunk(50);

        foreach ($chunks as $chunk) {
            DB::table('users')->insert($chunk->makeVisible('password')->toArray());
        }

    }
}
