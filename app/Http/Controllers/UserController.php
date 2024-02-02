<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Http\Requests\{RegisterRequest, LoginRequest};
use Illuminate\Support\Facades\{Auth, Session};
use Illuminate\Support\Facades\Log;

class UserController extends Controller
{
    /**
     * Handle account registration request
     * 
     * @param RegisterRequest $request
     * 
     */
    public function register(RegisterRequest $request)
    {
        try {

            $user = User::create($request->validated());
            auth()->login($user);

        } catch (\Exception $e) {
            //this response indicates that register validation passed but registration failed for different reason
            Log::channel('api')->info("unauthorized, registration failed, " . $e->getMessage());
            return response()->json(['errors' => "unauthorized" ,'message'=>$e->getMessage()], 401);
        }

        return response()->json(['success' => "Account successfully registered." ,'user'=>$user], 200);
    }

    /**
     * Handle account login request
     * 
     * @param LoginRequest $request
     * 
     */
    public function login(LoginRequest $request)
    {
        $credentials = $request->getCredentials();

        if (!Auth::validate($credentials)) {
            //this indicates that login validation passed but credentials are not matched
            Log::channel('api')->info("unauthorized, Account login failed.".trans('auth.failed'));
            return response()->json(['errors' => "unauthorized" ,'message'=>trans('auth.failed')], 401);
        }

        try {

            $user = Auth::getProvider()->retrieveByCredentials($credentials);

            Session::flush();
            Auth::login($user);
            $success['token'] =  $user->createToken('MyApp')->accessToken;

        } catch (\Exception $e) {
            //this response indicates that login validation passed & credentials matched but login failed for different reason
            Log::channel('api')->info("unauthorized, Account login failed, " . $e->getMessage());
            return response()->json(['error' => "unauthorized" ,'message'=>"authentication failed"], 401);

        }

        return response()->json(['success' => $success ,'user'=>$user], 200);

    }

    /**
     * Log out account user.
     *
     * @return \Illuminate\Http\Response
     */
    public function logout()
    {
        try {

            Session::flush();
            Auth::logout();

        } catch (\Exception $e) {
            //this response indicates that logout failed
            Log::channel('api')->info("logout failed, " . $e->getMessage());
            return response()->json(['error' => "logout failed" ,'message'=>$e->getMessage()], 400);

        }

        return response()->json(['success' => "Account successfully logged out."], 200);
    }

}