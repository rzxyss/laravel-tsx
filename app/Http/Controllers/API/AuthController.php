<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;

/**
 * @OA\SecurityScheme(
 *     type="http",
 *     description="Authentication with username and password",
 *     name="Token",
 *     in="header",
 *     scheme="bearer",
 *     bearerFormat="JWT",
 *     securityScheme="apiAuth",
 * )
 */
class AuthController extends Controller
{
    /**
     * @OA\Post(
     * path="/api/login",
     * operationId="authLogin",
     * tags={"Auth"},
     * summary="User Authentication",
     * description="Service get token",
     *    @OA\RequestBody(
     *      @OA\JsonContent(
     *        type="object",
     *        required={"username", "password"},
     *        @OA\Property(property="username", type="string"),
     *        @OA\Property(property="password", type="string"),
     *      )
     *    ),
     * @OA\Response(response="200", description="Return token bearer.",
     *          @OA\JsonContent(
     *          type="object",
     *          @OA\Property(property="status", type="string", example="200"),
     *          @OA\Property(property="message", type="string", example="Successfully"),
     *               @OA\Property(
     *               property="data",
     *               type="object",
     *               @OA\Property(property="token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwaS1hcHBzLnRlc3QvYXBpL2xvZ2luIiwiaWF0IjoxNzQ3OTI3NDI1LCJleHAiOjE3NDc5MzEwMjUsIm5iZiI6MTc0NzkyNzQyNSwianRpIjoiT1paWmw0bmp2UlJGNkc4ZiIsInN1YiI6IjEiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3IiwidHlwZSI6ImFjY2VzcyJ9.YS8cvi9yLvsE-nhp2VEPHcZVbbDdmDWT2mfrLhNbPXE"),
     *               @OA\Property(property="refresh_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwaS1hcHBzLnRlc3QvYXBpL2xvZ2luIiwiaWF0IjoxNzQ3OTI3NDI2LCJleHAiOjE3NDkxMzcwMjYsIm5iZiI6MTc0NzkyNzQyNiwianRpIjoibWhIMlZ4Q2NPSEFldDRiVCIsInN1YiI6IjEiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3IiwidHlwZSI6InJlZnJlc2gifQ.Zi3mj9912qX06tFukhG2PxTIZug-UjWO6m2CRbq2q1Y"),
     *               @OA\Property(property="token_type", type="string", example="bearer"),
     *               @OA\Property(property="user", type="object",
     *                    @OA\Property(property="id", type="integer", example="1"),
     *                    @OA\Property(property="name", type="string", example="Anisa Putri Setyaningrum"),
     *                    @OA\Property(property="email", type="string", example="anisaputris@gmail.com"),
     *                    @OA\Property(property="email_verified_at", type="string", example="2023-09-14T08:32:45.000000Z"),
     *                    @OA\Property(property="created_at", type="string", example="2023-09-14T08:32:45.000000Z"),
     *                    @OA\Property(property="updated_at", type="string", example="2023-09-14T08:32:45.000000Z"),
     *                    @OA\Property(property="username", type="string", example="massidiqf"),
     *                    @OA\Property(property="roles", type="array", @OA\Items(
     *                         @OA\Property(property="id", type="integer", example="1"),
     *                         @OA\Property(property="name", type="string", example="Superadmin"),
     *                         @OA\Property(property="guard_name", type="string", example="api"),
     *                         @OA\Property(property="created_at", type="string", example="2023-09-14T08:32:45.000000Z"),
     *                         @OA\Property(property="updated_at", type="string", example="2023-09-14T08:32:45.000000Z"),
     *                         @OA\Property(property="pivot", type="object",
     *                              @OA\Property(property="model_type", type="string", example="App\\Models\\User"),
     *                              @OA\Property(property="model_id", type="integer", example="1"),
     *                              @OA\Property(property="role_id", type="integer", example="1"),
     *                         ),
     *                         @OA\Property(property="permissions", type="array", @OA\Items(
     *                              @OA\Property(property="id", type="integer", example="1"),
     *                              @OA\Property(property="name", type="string", example="role"),
     *                              @OA\Property(property="guard_name", type="string", example="api"),
     *                              @OA\Property(property="created_at", type="string", example="2023-09-14T08:32:45.000000Z"),
     *                              @OA\Property(property="updated_at", type="string", example="2023-09-14T08:32:45.000000Z"),
     *                              @OA\Property(property="pivot", type="object",
     *                              @OA\Property(property="role_id", type="integer", example="1"),
     *                              @OA\Property(property="permission_id", type="integer", example="1"),
     *                          ),
     *                        )
     *                      ),
     *                    )
     *                ),
     *            )
     *         )
     *      )
     *   )
     * )
     */
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


    /**
     * @OA\Post(
     * path="/api/refresh-token",
     * tags={"Auth"},
     * summary="Refresh Token User",
     * description="service call when token is expired",
     * security={{ "apiAuth": {} }},
     * @OA\Response(response="200", description="Return token bearer.",
     *          @OA\JsonContent(
     *          type="object",
     *          @OA\Property(property="status", type="string", example="200"),
     *          @OA\Property(property="message", type="string", example="Successfully"),
     *               @OA\Property(
     *               property="data",
     *               type="object",
     *               @OA\Property(property="token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwaS1hcHBzLnRlc3QvYXBpL2xvZ2luIiwiaWF0IjoxNzQ3OTI3NDI1LCJleHAiOjE3NDc5MzEwMjUsIm5iZiI6MTc0NzkyNzQyNSwianRpIjoiT1paWmw0bmp2UlJGNkc4ZiIsInN1YiI6IjEiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3IiwidHlwZSI6ImFjY2VzcyJ9.YS8cvi9yLvsE-nhp2VEPHcZVbbDdmDWT2mfrLhNbPXE"),
     *               @OA\Property(property="refresh_token", type="string", example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwaS1hcHBzLnRlc3QvYXBpL2xvZ2luIiwiaWF0IjoxNzQ3OTI3NDI2LCJleHAiOjE3NDkxMzcwMjYsIm5iZiI6MTc0NzkyNzQyNiwianRpIjoibWhIMlZ4Q2NPSEFldDRiVCIsInN1YiI6IjEiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3IiwidHlwZSI6InJlZnJlc2gifQ.Zi3mj9912qX06tFukhG2PxTIZug-UjWO6m2CRbq2q1Y"),
     *               @OA\Property(property="token_type", type="string", example="bearer"),
     *               @OA\Property(property="user", type="object",
     *                    @OA\Property(property="id", type="integer", example="1"),
     *                    @OA\Property(property="name", type="string", example="Anisa Putri Setyaningrum"),
     *                    @OA\Property(property="email", type="string", example="anisaputris@gmail.com"),
     *                    @OA\Property(property="email_verified_at", type="string", example="2023-09-14T08:32:45.000000Z"),
     *                    @OA\Property(property="created_at", type="string", example="2023-09-14T08:32:45.000000Z"),
     *                    @OA\Property(property="updated_at", type="string", example="2023-09-14T08:32:45.000000Z"),
     *                    @OA\Property(property="username", type="string", example="anisaps"),
     *                    @OA\Property(property="roles", type="array", @OA\Items(
     *                         @OA\Property(property="id", type="integer", example="1"),
     *                         @OA\Property(property="name", type="string", example="Superadmin"),
     *                         @OA\Property(property="guard_name", type="string", example="api"),
     *                         @OA\Property(property="created_at", type="string", example="2023-09-14T08:32:45.000000Z"),
     *                         @OA\Property(property="updated_at", type="string", example="2023-09-14T08:32:45.000000Z"),
     *                         @OA\Property(property="pivot", type="object",
     *                              @OA\Property(property="model_type", type="string", example="App\\Models\\User"),
     *                              @OA\Property(property="model_id", type="integer", example="1"),
     *                              @OA\Property(property="role_id", type="integer", example="1"),
     *                         ),
     *                         @OA\Property(property="permissions", type="array", @OA\Items(
     *                              @OA\Property(property="id", type="integer", example="1"),
     *                              @OA\Property(property="name", type="string", example="role"),
     *                              @OA\Property(property="guard_name", type="string", example="api"),
     *                              @OA\Property(property="created_at", type="string", example="2023-09-14T08:32:45.000000Z"),
     *                              @OA\Property(property="updated_at", type="string", example="2023-09-14T08:32:45.000000Z"),
     *                              @OA\Property(property="pivot", type="object",
     *                              @OA\Property(property="role_id", type="integer", example="1"),
     *                              @OA\Property(property="permission_id", type="integer", example="1"),
     *                          ),
     *                        )
     *                      ),
     *                    )
     *                ),
     *            )
     *         )
     *      )
     *   )
     * )
     */
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
