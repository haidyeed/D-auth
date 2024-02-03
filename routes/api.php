<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::get('/user', [UserController::class, 'getUserData'])->name('user');

Route::post("register",[UserController::class,'register']);

Route::post('login', [UserController::class,'login'])->name('login');

Route::group(['middleware' => 'auth:api'], function(){

    Route::get('/logout', [UserController::class, 'logout'])->name('user.logout');

});
