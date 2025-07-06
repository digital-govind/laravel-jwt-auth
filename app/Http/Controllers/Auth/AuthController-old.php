<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\MobileDevice;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\ValidationException;
use Illuminate\Http\JsonResponse;
use Exception;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache; // for Redis
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Redis;
use Symfony\Component\HttpFoundation\Response as HttpResponse;

class AuthController extends Controller
{
    
    public function signin(Request $request): JsonResponse
    {
        try {

            $validatedData = $request->validate([
                'email' => 'required|email',
                'password' => 'required|min:5',
            ], [
                'email.required' => 'Email field is required.',
                'email.email' => 'Email field must be a valid email address.',
                'password.required' => 'Password field is required.',
            ]);
    
            // $user = User::find(1);
            // $user->password = Hash::make('12345678');
            // $user->save();

            // die;
            
            $credentials = $request->only('email', 'password');
            $remember = $request->filled('remember');
    
            // Try logging in using default guard ('web' or set it explicitly)
            if (!Auth::attempt($credentials, $remember)) {
                return response()->json([
                    'message' => 'Invalid credentials.'
                ], 401);
            }

            $req_user  = $request->only(['user.source', 'user.email', 'user.password', 'user.social_id'])['user'];
            $device = $request->only([
                'device.type',
                'device.device_id',
                'device.app_version',
                'device.token',
                'device.status',
                'device.os_version',
                'device.device_model',
                'device.device_make',
                'device.resolution',
                'device.screen_width',
                'device.screen_height',
                'device.ram',
                'device.dpi',
                'device.user_id',
                'device.brand',
        
            ])['device'];

            switch ($req_user['source']) {
                case 1:
                    return $this->signInWithPassword($device, $req_user);
                    break;
                case 2:
                   // return $sign_in->signInWithOTP();
                    break;
    
                    // social login google|facebook|apple
                case 3:
                case 4:
                case 5:
                  //  return $sign_in->signInWithSocial();
                    break;
            }
    
            $user = Auth::user();
            
            if($user){
                
                $auth_key = str_random(36);
                
    
                Redis::set(getRedisKey('auth', $auth_key), $user->id, 'EX', 2592000);
              
                Redis::set(getRedisKey('user', $user->id), json_encode(User::find($user->id)));

                //store user device detail

                //store user login request
            }

    
            // Store user session in Redis for quick retrieval (optional: add TTL)
        //    Cache::put('user_session_' . $user->id, $user, now()->addHours(2));
    
            return response()->json([
                'message' => 'Login successful.',
                'data' => ["user" => $user, "auth_key" => $auth_key]
            ]);
    
        } catch (ValidationException $e) {
            return response()->json([
                'errors' => $e->errors(),
                'message' => 'Validation failed.'
            ], 422);
        } catch (Exception $e) {
            Log::error('API Login Error: ' . $e->getMessage());
    
            return response()->json([
                'message' => 'Server error. Please try again.'
            ], 500);
        }
    }


    public function signInWithPassword($device,$user){
       
        $errObj = new stdClass;

        $this->userByDynamicField($this->req_user['mobile']);
        $this->login_request = $this->logInRequest($this->req_user['source']);

        if (!Hash::check($this->req_user['password'], $this->user->password)) {
            $errObj->message = "Password does not match";
            $this->login_request->message = "Password does not match";
            $this->login_request->save();
            return Response::json(exceptionResponce('ValidationException', $errObj), IlluminateResponse::HTTP_UNPROCESSABLE_ENTITY)->send();
        }

        // Change and save auth key in redis
        return $this->saveNewAuthKey()->addDevice()->getResponse();
    }

    protected function logInRequest(int $source)
    {
        $login_request = new LoginRequest;
        $login_request->source = $source;
        $login_request->user_id = $this->user->id;
        $login_request->device = json_encode($this->device);
        $login_request->device_type = $this->device['type'];
        return $login_request;
    }

    protected function saveNewAuthKey($otp_verified = 0): SignInBase
    {


        $auth_key = str_random(36);
        $this->login_request->auth_key  = $auth_key;
        $this->login_request->otp_verified = $otp_verified;
        $this->login_request->expire_at  = Carbon::now()->addDays(30);
        $this->login_request->status = 1; //login successfull
        $this->login_request->save();


        if($otp_verified){  
        $this->user->is_mobile_verified = $otp_verified;
        $this->user->save();
        }


        $this->addDevice();
        // Save key for one month
        Redis::set(getRedisKey('auth', $auth_key), $this->user->id, 'EX', 2592000);

        Redis::set(getRedisKey('user', $this->user->id), json_encode(Account::myProfile($this->user->id)));

        return $this;
    }

    protected function addDevice()
    {

        $device = MobileDevice::where('token', '=', $this->device['token'])->where('user_id','=', $this->user->id)->first();

        if (!$device)
            $device = new MobileDevice;


        $device->type = $this->device['type'];
        $device->app_version = $this->device['app_version'];
        $device->device_id = $this->device['device_id'];
        $device->token = $this->device['token'];
        $device->status = 1;
        $device->user_id = $this->user->id;
        $device->os_version = $this->device['os_version'];
        $device->device_model = $this->device['device_model'];
        $device->device_make = $this->device['device_make'];
        $device->resolution = $this->device['resolution'];
        $device->screen_width = $this->device['screen_width'];
        $device->screen_height = $this->device['screen_height'];
        $device->ram = $this->device['ram'];
        $device->dpi = $this->device['dpi'];
        $device->brand = $this->device['brand'];
        $device->save();

        return $this;
    }
    
    public function register(Request $request)
    {
        $authKey = $request->header('AuthKey');

        if (!$authKey) {
            return response()->json(['message' => 'Missing auth key'], HttpResponse::HTTP_BAD_REQUEST);
        }

        $user_id = Redis::get(getRedisKey('auth', $authKey));


        if (!$user_id) {
            return response()->json(['message' => 'Unauthorized'], HttpResponse::HTTP_UNAUTHORIZED);
        }

        $user = Redis::get(getRedisKey('user', $user_id));

        if (!$user) {
            return response()->json(['message' => 'User not found'], HttpResponse::HTTP_UNAUTHORIZED);
        }

        // If user is in JSON, decode it
        $user = is_string($user) ? json_decode($user, true) : $user;

        return response()->json([
            'message' => 'User verified',
            'user' => $user
        ], HttpResponse::HTTP_OK);
    }


    public function testRedis()
    {
        //Redis::set('test_key', 'Hello Redis');

      //  $value = Redis::get('test_key');
        $value = Redis::get(getRedisKey('auth', "CLGQSSB8dRYMDSpl3erJmWSLF6VqVUZUTMLG"));

        if ($value) {
            return response()->json(['success' => true, 'value' => $value]);
        } else {
            return response()->json(['success' => false, 'message' => 'Key not found']);
        }
        
    }

}