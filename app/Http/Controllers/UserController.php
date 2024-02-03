<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Http\Requests\{RegisterRequest, LoginRequest};
use Illuminate\Support\Facades\{Auth, Session};
use Illuminate\Support\Facades\Log;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

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


    /**
     * get user data.
     *
     * @return \Illuminate\Http\Response
     */
    public function getUserData(Request $request)
    {
        //does request has token ? 
        if(!$request->hasHeader('authorization')){
            return response()->json(['response' =>['errors' => "unauthorized" ,'message'=>'no token found for authorization','user_id'=> 0], 401]);
        }

        $access_token = $request->header('Authorization');
        $auth_header = explode(' ', $access_token);
        $token = $auth_header[1];
        $token_parts = explode('.', $token);
        $token_header = $token_parts[1];
        $token_header_json = base64_decode($token_header);
        $token_header_array = json_decode($token_header_json, true);
        $token_id = $token_header_array['jti'];
  
        $user_data = DB::table('oauth_access_tokens')->where('id', $token_id)->first();

        if($user_data->user_id != Auth::guard('api')->id()){
            //in case user is found but not authenticated
            return response()->json(['response' =>['errors' => "access forbidden" ,'message'=>'token found but not authorized','user_id'=> 0], 403]);
        }
  
        return response()->json(['response' =>['success' => "authorized" ,'message'=>'token verified', 'user_id'=>$user_data->user_id, 'errors'=>'none'], 200]);
    }

}