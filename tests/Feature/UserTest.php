<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\DatabaseTransactions;
use App\Models\User;
use Tests\TestCase;


class UserTest extends TestCase
{
    use DatabaseTransactions;

    public function test_user_can_register_with_valid_credentials()
    {

        $registerResponse = $this->post('/api/register', [
            'email' => 'test@mail.com',
            'name' => 'haidy',
            'password' => 12345678,
            'password_confirmation' => 12345678
        ]);

        $registerResponse->assertSessionHasNoErrors();
        $registerResponse->assertStatus(200);

    }

        public function test_user_cannot_register_with_invalid_credentials()
    {

        $registerResponse = $this->post('/api/register', [
            'email' => 'test@mail.com',
            'name' => 'haidy',
            'password' => 1234567890,
            'password_confirmation' => 12345678
        ]);

        $registerResponse->assertStatus(422);

    }

        public function test_user_can_login_with_valid_credentials()
    {
        User::factory()->create([
            'name' => 'valid-name',
            'password' => 'valid-password',
        ]);

        $response = $this->post('/api/login', [
            'name' => 'valid-name',
            'password' => 'valid-password',
        ]);

        $response->assertSessionHasNoErrors();
        $response->assertStatus(200);

    }

    public function test_user_cannot_login_with_invalid_credentials()
    {
        User::factory()->create([
            'name' => 'valid-name',
            'password' => 'valid-password',
        ]);

        $response = $this->post('/api/login', [
            'name' => 'invalid-name',
        ]);

        $response->assertStatus(422);
    }

    public function test_user_cannot_login_with_non_matched_credentials()
    {
        $user = User::factory()->create([
            'name' => 'valid-name',
            'password' => 'valid-password',
        ]);

        $response = $this->post('/api/login', [
            'name' => 'invalid-name',
            'password' => 'invalid-password',
        ]);

        $response->assertStatus(401);
    }
}
