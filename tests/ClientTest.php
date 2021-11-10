<?php

declare(strict_types=1);

namespace BPM\Etcd\Tests;

use BPM\Etcd\Client;
use PHPUnit\Framework\TestCase;

use function in_array;

class ClientTest extends TestCase
{
    private Client $client;
    private string $key = '/test';
    private string $role = 'root';
    private string $user = 'root';
    private string $password = '123456';

    protected function setUp(): void
    {
        $this->client = new Client();
        $this->client->setPretty(true);
    }

    public function testPutAndRange(): void
    {
        $value = 'testput';
        $this->client->put($this->key, $value);

        $body = $this->client->get($this->key);
        $this->assertArrayHasKey($this->key, $body);
        $this->assertEquals($value, $body[$this->key]);
    }

    public function testGetAllKeys(): void
    {
        $body = $this->client->getAllKeys();
        $this->assertNotEmpty($body);
    }

    public function testGetKeysWithPrefix(): void
    {
        $body = $this->client->getKeysWithPrefix('/');
        $this->assertNotEmpty($body);
    }

    public function testDeleteRange(): void
    {
        $this->client->del($this->key);
        $body = $this->client->get($this->key);
        $this->assertArrayNotHasKey($this->key, $body);
    }

    public function testGrant(): void
    {
        $body = $this->client->grant(3600);
        $this->assertArrayHasKey('ID', $body);
        $id = (int) $body['ID'];

        $body = $this->client->timeToLive($id);
        $this->assertArrayHasKey('ID', $body);

        $this->client->keepAlive($id);
        $this->assertArrayHasKey('ID', $body);

        $this->client->revoke($id);
    }

    public function testAddRole(): void
    {
        $this->client->addRole($this->role);
    }

    public function testAddUser(): void
    {
        $this->client->addUser($this->user, $this->password);
    }

    public function testChangeUserPassword(): void
    {
        $this->client->changeUserPassword($this->user, '456789');
        $this->client->changeUserPassword($this->user, $this->password);
    }

    public function testGrantUserRole(): void
    {
        $this->client->grantUserRole($this->user, $this->role);
    }

    public function testGetRole(): void
    {
        $this->client->getRole($this->role);
    }

    public function testRoleList(): void
    {
        $body = $this->client->roleList();
        if (!in_array($this->role, $body)) {
            $this->fail('role not exist');
        }
    }

    public function testGetUser(): void
    {
        $this->client->getUser($this->user);
    }

    public function testUserList(): void
    {
        $body = $this->client->userList();
        if (!in_array($this->user, $body)) {
            $this->fail('user not exist');
        }
    }

    public function testGrantRolePermission(): void
    {
        $this->client->grantRolePermission($this->role,
            Client::PERMISSION_READWRITE, '\0', 'z' );
    }

    public function testAuthenticate(): void
    {
        $this->client->authEnable();
        $token = $this->client->authenticate($this->user, $this->password);
        $this->client->setToken($token);
        $this->client->addUser('admin', '345678');
        $this->client->addRole('admin');
        $this->client->grantUserRole('admin', 'admin');

        $this->client->authDisable();
        $this->client->deleteRole('admin');
        $this->client->deleteUser('admin');
    }

    public function testRevokeRolePermission(): void
    {
        $this->client->revokeRolePermission($this->role, '\0', 'z');
    }

    public function testRevokeUserRole(): void
    {
        $this->client->revokeUserRole($this->user, $this->role);
    }

    public function testDeleteRole(): void
    {
        $this->client->deleteRole($this->role);
    }

    public function testDeleteUser(): void
    {
        $this->client->deleteUser($this->user);
    }
}
