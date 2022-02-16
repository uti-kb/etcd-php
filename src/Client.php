<?php

namespace BPM\Etcd;

use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;

class Client
{
    // KV
    private const URI_PUT = 'kv/put';
    private const URI_RANGE = 'kv/range';
    private const URI_DELETE_RANGE = 'kv/deleterange';
    private const URI_COMPACTION = 'kv/compaction';

    // Lease
    private const URI_GRANT = 'lease/grant';
    private const URI_REVOKE = 'kv/lease/revoke';
    private const URI_KEEPALIVE = 'lease/keepalive';
    private const URI_TIMETOLIVE = 'kv/lease/timetolive';

    // Role
    private const URI_AUTH_ROLE_ADD = 'auth/role/add';
    private const URI_AUTH_ROLE_GET = 'auth/role/get';
    private const URI_AUTH_ROLE_DELETE = 'auth/role/delete';
    private const URI_AUTH_ROLE_LIST = 'auth/role/list';

    // Authenticate
    private const URI_AUTH_ENABLE = 'auth/enable';
    private const URI_AUTH_DISABLE = 'auth/disable';
    private const URI_AUTH_AUTHENTICATE = 'auth/authenticate';

    // User
    private const URI_AUTH_USER_ADD = 'auth/user/add';
    private const URI_AUTH_USER_GET = 'auth/user/get';
    private const URI_AUTH_USER_DELETE = 'auth/user/delete';
    private const URI_AUTH_USER_CHANGE_PASSWORD = 'auth/user/changepw';
    private const URI_AUTH_USER_LIST = 'auth/user/list';

    private const URI_AUTH_ROLE_GRANT = 'auth/role/grant';
    private const URI_AUTH_ROLE_REVOKE = 'auth/role/revoke';

    private const URI_AUTH_USER_GRANT = 'auth/user/grant';
    private const URI_AUTH_USER_REVOKE = 'auth/user/revoke';

    public const PERMISSION_READWRITE = 2;

    private const DEFAULT_HTTP_TIMEOUT = 30;

    /** @var string host:port */
    private string $server;

    /** @var string api version */
    private string $version;

    private array $httpOptions;
    private bool $pretty = false;

    /** @var ?string auth token */
    private ?string $token = null;

    public function __construct(string $server = '127.0.0.1:2379', string $version = 'v3alpha')
    {
        $this->server = rtrim($server, "/");
        if (strpos($this->server, 'http') !== 0) {
            $this->server = 'http://' . $this->server;
        }
        $this->version = trim($version);
    }

    public function setHttpOptions(array $options): void
    {
        $this->httpOptions = $options;
    }

    public function setPretty(bool $enabled): void
    {
        $this->pretty = $enabled;
    }

    public function setToken(string $token): void
    {
        $this->token = $token;
    }

    public function clearToken(): void
    {
        $this->token = null;
    }

    /**
     * Put puts the given key into the key-value store.
     * A put request increments the revision of the key-value
     * store\nand generates one event in the event history.
     *
     * @param array  $options 可选参数
     *        int64  lease
     *        bool   prev_kv
     *        bool   ignore_value
     *        bool   ignore_lease
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function put(string $key, string $value, array $options = []): array
    {
        $body = $this->request(
            self::URI_PUT,
            $this->encode(['key' => $key, 'value' => $value]),
            $this->encode($options),
        );

        $body = $this->decodeBodyForFields(
            $body,
            'prev_kv',
            ['key', 'value',]
        );

        return (isset($body['prev_kv']) && $this->pretty) ? $this->convertFields($body['prev_kv']) : $body;
    }

    /**
     * Gets the key or a range of keys
     *
     * @param  array $options
     *         string range_end
     *         int    limit
     *         int    revision
     *         int    sort_order
     *         int    sort_target
     *         bool   serializable
     *         bool   keys_only
     *         bool   count_only
     *         int64  min_mod_revision
     *         int64  max_mod_revision
     *         int64  min_create_revision
     *         int64  max_create_revision
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function get(string $key, array $options = []): array
    {
        $body = $this->decodeBodyForFields(
            $this->request(self::URI_RANGE, $this->encode(['key' => $key]), $this->encode($options)),
            'kvs',
            ['key', 'value',]
        );

        return (isset($body['kvs']) && $this->pretty) ? $this->convertFields($body['kvs']) : $body;
    }

    /**
     * get all keys
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function getAllKeys(): array
    {
        return $this->get("\0", ['range_end' => "\0"]);
    }

    /**
     * get all keys with prefix
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function getKeysWithPrefix(string $prefix): array
    {
        $prefix = trim($prefix);
        if (!$prefix) {
            return [];
        }
        $lastIndex = strlen($prefix) - 1;
        $rangeEnd = $prefix;
        $rangeEnd[$lastIndex] = chr(ord($prefix[$lastIndex]) + 1);

        return $this->get($prefix, ['range_end' => $rangeEnd]);
    }

    /**
     * Removes the specified key or range of keys
     *
     * @param array  $options
     *        string range_end
     *        bool   prev_kv
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function del(string $key, array $options = []): array
    {
        $body = $this->decodeBodyForFields(
            $this->request(self::URI_DELETE_RANGE, $this->encode(['key' => $key]), $this->encode($options)),
            'prev_kvs',
            ['key', 'value',]
        );

        return (isset($body['prev_kvs']) && $this->pretty) ? $this->convertFields($body['prev_kvs']) : $body;
    }

    /**
     * Compact compacts the event history in the etcd key-value store.
     * The key-value\nstore should be periodically compacted
     * or the event history will continue to grow\nindefinitely.
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function compaction(int $revision, bool $physical = false): array
    {
        return $this->request(self::URI_COMPACTION, ['revision' => $revision, 'physical' => $physical]);
    }

    /**
     * LeaseGrant creates a lease which expires if the server does not receive a
     * keepAlive\nwithin a given time to live period. All keys attached to the lease
     * will be expired and\ndeleted if the lease expires.
     * Each expired key generates a delete event in the event history.
     *
     * @param int $ttl  TTL is the advisory time-to-live in seconds.
     * @param int $id   ID is the requested ID for the lease.
     *                    If ID is set to 0, the lessor chooses an ID.
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function grant(int $ttl, int $id = 0): array
    {
        return $this->request(self::URI_GRANT, ['TTL' => $ttl, 'ID' => $id]);
    }

    /**
     * revokes a lease. All keys attached to the lease will expire and be deleted.
     *
     * @param int  $id ID is the lease ID to revoke. When the ID is revoked,
     *               all associated keys will be deleted.
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function revoke(int $id): array
    {
        return $this->request(self::URI_REVOKE, ['ID' => $id]);
    }

    /**
     * keeps the lease alive by streaming keep alive requests
     * from the client\nto the server and streaming keep alive responses
     * from the server to the client.
     *
     * @param int $id  ID is the lease ID for the lease to keep alive.
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function keepAlive(int $id): array
    {
        $body = $this->request(self::URI_KEEPALIVE, ['ID' => $id]);

        return isset($body['result']) ? ['ID' => $body['result']['ID'], 'TTL' => $body['result']['TTL']] : $body;
    }

    /**
     * retrieves lease information.
     *
     * @param int $id ID is the lease ID for the lease.
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function timeToLive(int $id, bool $keys = false): array
    {
        $body = $this->request(self::URI_TIMETOLIVE, ['ID' => $id, 'keys' => $keys]);

        if (isset($body['keys'])) {
            $body['keys'] = array_map(static function($value) {
                return base64_decode($value);
            }, $body['keys']);
        }

        return $body;
    }

    /**
     * enable authentication
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function authEnable(): array
    {
        $body = $this->request(self::URI_AUTH_ENABLE);
        $this->clearToken();

        return $body;
    }

    /**
     * disable authentication
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function authDisable(): array
    {
        $body = $this->request(self::URI_AUTH_DISABLE);
        $this->clearToken();

        return $body;
    }

    /**
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function authenticate(string $user, string $password): array
    {
        $body = $this->request(self::URI_AUTH_AUTHENTICATE, ['name' => $user, 'password' => $password]);

        return ($this->pretty && isset($body['token'])) ? $body['token'] : $body;
    }

    /**
     * add a new role.
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function addRole(string $name): array
    {
        return $this->request(self::URI_AUTH_ROLE_ADD, ['name' => $name]);
    }

    /**
     * get detailed role information.
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function getRole(string $role): array
    {
        $body = $this->decodeBodyForFields(
            $this->request(self::URI_AUTH_ROLE_GET, ['role' => $role]),
            'perm',
            ['key', 'range_end',]
        );

        return ($this->pretty && isset($body['perm'])) ?  $body['perm'] : $body;
    }

    /**
     * delete a specified role.
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function deleteRole(string $role): array
    {
        return $this->request(self::URI_AUTH_ROLE_DELETE, ['role' => $role]);
    }

    /**
     * get lists of all roles
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function roleList(): array
    {
        $body = $this->request(self::URI_AUTH_ROLE_LIST);

        return ($this->pretty && isset($body['roles'])) ?  $body['roles'] : $body;
    }

    /**
     * add a new user
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function addUser(string $user, string $password): array
    {
        return $this->request(self::URI_AUTH_USER_ADD, ['name' => $user, 'password' => $password]);
    }

    /**
     * get detailed user information
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function getUser(string $user): array
    {
        $body = $this->request(self::URI_AUTH_USER_GET, ['name' => $user]);

        return ($this->pretty && isset($body['roles'])) ?  $body['roles'] : $body;
    }

    /**
     * delete a specified user
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function deleteUser(string $user): array
    {
        return $this->request(self::URI_AUTH_USER_DELETE, ['name' => $user]);
    }

    /**
     * get a list of all users.
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function userList(): array
    {
        $body = $this->request(self::URI_AUTH_USER_LIST);

        return ($this->pretty && isset($body['users'])) ? $body['users'] : $body;
    }

    /**
     * change the password of a specified user.
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function changeUserPassword(string $user, string $password): array
    {
        return $this->request(self::URI_AUTH_USER_CHANGE_PASSWORD, ['name' => $user, 'password' => $password]);
    }

    /**
     * grant a permission of a specified key or range to a specified role.
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function grantRolePermission(string $role, int $permType, string $key, ?string $rangeEnd = null): array
    {
        $params = [
            'name' => $role,
            'perm' => [
                'permType' => $permType,
                'key' => base64_encode($key),
            ],
        ];
        if ($rangeEnd !== null) {
            $params['perm']['range_end'] = base64_encode($rangeEnd);
        }

        return $this->request(self::URI_AUTH_ROLE_GRANT, $params);
    }

    /**
     * revoke a key or range permission of a specified role.
     *
     * @throws BadResponseException
     * @throws JsonException
     * @throws GuzzleException
     */
    public function revokeRolePermission(string $role, string $key, ?string $rangeEnd = null): array
    {
        $params = [
            'role' => $role,
            'key' => $key,
        ];
        if ($rangeEnd !== null) {
            $params['range_end'] = $rangeEnd;
        }

        return $this->request(self::URI_AUTH_ROLE_REVOKE, $params);
    }

    /**
     * grant a role to a specified user.
     *
     * @throws GuzzleException
     * @throws JsonException
     */
    public function grantUserRole(string $user, string $role): array
    {
        return $this->request(self::URI_AUTH_USER_GRANT, ['user' => $user, 'role' => $role]);
    }

    /**
     * revoke a role of specified user.
     *
     * @throws GuzzleException
     * @throws JsonException
     */
    public function revokeUserRole(string $user, string $role): array
    {
        return $this->request(self::URI_AUTH_USER_REVOKE, ['name' => $user, 'role' => $role]);
    }

    // endregion auth

    /**
     * 发送HTTP请求
     *
     * @throws BadResponseException
     * @throws GuzzleException
     * @throws JsonException
     */
    protected function request(string $uri, array $params = [], array $options = []): array
    {
        if ($options !== []) {
            $params = array_merge($params, $options);
        }
        // 没有参数, 设置一个默认参数
        if ($params !== []) {
            $params['php-etcd-client'] = 1;
        }

        $data = ['json' => $params];
        if ($this->token) {
            $data['headers'] = ['Grpc-Metadata-Token' => $this->token];
        }

        $body = json_decode(
            $this->getHttpClient()->request('post', $uri, $data)->getBody()->getContents(),
            true,
            512,
            JSON_THROW_ON_ERROR
        );

        if ($this->pretty && isset($body['header'])) {
            unset($body['header']);
        }

        return $body;
    }

    protected function getHttpClient(): HttpClient
    {
        static $httpClient = null;
        if ($httpClient !== null) {
            return $httpClient;
        }
        $baseUri = sprintf('%s/%s/', $this->server, $this->version);
        $this->httpOptions['base_uri'] = $baseUri;
        if (!array_key_exists('timeout', $this->httpOptions)) {
            $this->httpOptions['timeout'] = self::DEFAULT_HTTP_TIMEOUT;
        }
        return new HttpClient($this->httpOptions);
    }

    /**
     * string类型key用base64编码
     */
    protected function encode(array $data): array
    {
        foreach ($data as $key => $value) {
            if (is_string($value)) {
                $data[$key] = base64_encode($value);
            }
        }

        return $data;
    }

    /**
     * 指定字段base64解码
     *
     * @param array  $fields  需要解码的字段
     */
    protected function decodeBodyForFields(array $body, string $bodyKey, array $fields): array
    {
        if (!isset($body[$bodyKey])) {
            return $body;
        }
        $data = $body[$bodyKey];
        if (!isset($data[0])) {
            $data = array($data);
        }
        foreach ($data as $key => $value) {
            foreach ($fields as $field) {
                if (isset($value[$field])) {
                    $data[$key][$field] = base64_decode($value[$field]);
                }
            }
        }

        if (isset($body[$bodyKey][0])) {
            $body[$bodyKey] = $data;
        } else {
            $body[$bodyKey] = $data[0];
        }

        return $body;
    }

    protected function convertFields(array $data): array
    {
        if (!isset($data[0])) {
            return $data['value'];
        }

        $map = [];
        foreach ($data as $value) {
            $key = $value['key'];
            $map[$key] = $value['value'];
        }

        return $map;
    }
}
