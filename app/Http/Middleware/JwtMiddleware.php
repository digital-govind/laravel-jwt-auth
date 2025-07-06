<?php

namespace App\Http\Middleware;

use Closure;
use Exception;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;
use Tymon\JWTAuth\Exceptions\JWTException;

class JwtMiddleware extends BaseMiddleware
{
    public function handle(Request $request, Closure $next)
    {
        try {

            
            // Check if token exists and is valid
            $user = JWTAuth::parseToken()->authenticate();

            if (! $user) {
                return response()->json([
                    'success' => false,
                    'message' => 'User not found or unauthorized.'
                ], 401);
            }
        } catch (TokenExpiredException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Token has expired.'
            ], 401);
        } catch (TokenInvalidException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Token is invalid.'
            ], 401);
        } catch (JWTException $e) {
            return response()->json([
                'success' => false,
                'message' => 'Authorization token not provided.'
            ], 401);
        } catch (Exception $e) {
            return response()->json([
                'success' => false,
                'message' => 'Something went wrong with token authentication.'
            ], 500);
        }
        

        return $next($request);
    }
}
