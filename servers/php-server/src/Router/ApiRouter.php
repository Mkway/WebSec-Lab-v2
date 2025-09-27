<?php
/**
 * @OA\Info(
 *     title="WebSec-Lab PHP API",
 *     version="2.0.0",
 *     description="PHP Web Security Testing Platform"
 * )
 */

namespace WebSecLab\Router;

class ApiRouter
{
    private array $routes = [];

    public function get(string $path, callable $handler): void
    {
        $this->routes['GET'][$path] = $handler;
    }

    public function post(string $path, callable $handler): void
    {
        $this->routes['POST'][$path] = $handler;
    }

    public function route(string $method, string $path): mixed
    {
        if (!isset($this->routes[$method][$path])) {
            throw new \Exception("Route not found: $method $path");
        }

        return call_user_func($this->routes[$method][$path]);
    }

    public function getRoutes(): array
    {
        return $this->routes;
    }
}