<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        //
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     */
    public function show(string $id)
    {
        //
    }

    /**
     * Show the form for editing the specified resource.
     */
    public function edit(string $id)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, string $id)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        //
    }

    // public function login(Request $request)
    // {
    //     $credentials = $request->only('username', 'password');

    //     if (!$token = JWTAuth::attempt($credentials)) {
    //         return response()->json(['error' => 'Unauthorized'], 401);
    //     }

    //     return response()->json([
    //         'status' => '200',
    //         'message' => 'Successfully',
    //         'data' => [
    //             'access_token' => $token,
    //             'token_type' => 'bearer',
    //             'expires_in' => auth()->factory()->getTTL() * 60
    //         ]
    //     ], 200);
    // }
    public function login(Request $request)
    {
        $credentials = $request->only('username', 'password');

        if (!$token = Auth::attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        JWTAuth::factory()->setTTL(config('jwt.ttl'));
        $token = JWTAuth::claims(['type' => 'access'])->attempt($credentials);
        JWTAuth::factory()->setTTL(config('jwt.refresh_ttl'));
        $refresh_token = JWTAuth::claims(['type' => 'refresh'])->attempt($credentials);
        $user = Auth::user();
        $user->getAllPermissions();

        return response()->json([
            'status' => '200',
            'message' => 'Successfully',
            'data' => [
                'token' => $token,
                'refresh_token' => $refresh_token,
                'token_type' => 'bearer',
                'user' => $user,
            ]
        ], 200);
    }

    public function refreshToken(Request $request)
    {
        try {
            $token = $request->header('Authorization') ?: $request->refresh_token;
            if (!$token) {
                return response()->json(['status' => 400, 'message' => 'Token not provided'], 400);
            }
            $token = str_replace('Bearer ', '', $token);

            $payload = JWTAuth::setToken($token)->getPayload();

            if ($payload->get('type') !== 'refresh') {
                return response()->json(['status' => 401, 'message' => 'Invalid token type'], 401);
            }

            $user = JWTAuth::setToken($token)->authenticate();

            JWTAuth::factory()->setTTL(config('jwt.ttl'));
            $newAccessToken = JWTAuth::claims(['type' => 'access'])->fromUser($user);
            JWTAuth::factory()->setTTL(config('jwt.refresh_ttl'));
            $newRefreshToken = JWTAuth::claims(['type' => 'refresh'])->fromUser($user);

            $user->getAllPermissions();

            return response()->json([
                'status' => 200,
                'message' => 'Successfully refreshed token',
                'data' => [
                    'token' => $newAccessToken,
                    'refresh_token' => $newRefreshToken,
                    'token_type' => 'bearer',
                    'user' => $user,
                ],
            ], 200);
        } catch (\PHPOpenSourceSaver\JWTAuth\Exceptions\TokenBlacklistedException $e) {
            return response()->json(['status' => 401, 'message' => 'The token has been blacklisted'], 401);
        } catch (\PHPOpenSourceSaver\JWTAuth\Exceptions\TokenExpiredException $e) {
            return response()->json(['status' => 401, 'message' => 'Token is expired'], 401);
        } catch (\PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException $e) {
            return response()->json(['status' => 401, 'message' => 'Token is invalid'], 401);
        }
    }
}
