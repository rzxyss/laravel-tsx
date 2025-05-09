<?php

namespace App\Http\Controllers;


use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Inertia\Inertia;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

class RoleController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $roles = Role::with('permissions')->get(['id', 'name']);
        $permissions = Permission::all(['id', 'name']);
        return Inertia::render('Roles/index', [
            'roles' => $roles,
            'permissions' => $permissions,
            'authUser' => Auth::user()->load('roles'),
        ]);
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $request->validate([
            'name' => 'required|lowercase',
            'permissions' => 'required',
        ]);

        DB::beginTransaction();
        try {
            $role = new Role();
            $role->name = $request->name;
            $role->save();
            $role->syncPermissions($request->permissions);
            DB::commit();
            return redirect()->route('roles')->with('success', 'Role created successfully');
        } catch (\Exception $e) {
            DB::rollBack();
            return back()->with('error', 'Failed to create role');
        }
    }

    /**
     * Show the form for creating a new resource.
     */
    public function create()
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
        $validated = Validator::make($request->all(), [
            'name' => 'required|lowercase|max:255',
            'permissions' => 'required',
        ]);

        if ($validated->fails()) {
            return back()->with('error', 'Some data is not valid');
        }

        DB::beginTransaction();
        try {
            $role = Role::findOrFail($id);
            $role->name = $request->name;
            $role->save();
            $role->syncPermissions($request->permissions);
            DB::commit();
            return redirect()->route('roles')->with('success', 'Role updated successfully');
        } catch (\Exception $e) {
            DB::rollBack();
            return back()->with('error', 'Failed to update role');
        }
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy(string $id)
    {
        DB::beginTransaction();
        try {
            $role = Role::findOrFail($id);
            $role->delete();
            DB::commit();
            return redirect()->route('roles')->with('success', 'Role deleted successfully');
        } catch (\Exception $e) {
            DB::rollBack();
            return back()->with('error', 'Failed to delete role');
        }
    }
}
