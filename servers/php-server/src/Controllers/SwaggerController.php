<?php

namespace WebSecLab\Controllers;

class SwaggerController
{
    /**
     * Generate Swagger JSON documentation
     */
    public function generateSwaggerJson(): string
    {
        $swaggerJson = [
            'openapi' => '3.0.0',
            'info' => [
                'title' => 'WebSec-Lab PHP API',
                'description' => 'PHP 서버의 취약점 테스트 API',
                'version' => '2.0.0'
            ],
            'servers' => [
                [
                    'url' => 'http://localhost:8080',
                    'description' => 'PHP Development Server'
                ]
            ],
            'paths' => [
                '/health' => [
                    'get' => [
                        'summary' => 'Health check',
                        'responses' => [
                            '200' => [
                                'description' => 'Server is healthy',
                                'content' => [
                                    'application/json' => [
                                        'schema' => [
                                            'type' => 'object',
                                            'properties' => [
                                                'status' => ['type' => 'string'],
                                                'server' => ['type' => 'string'],
                                                'timestamp' => ['type' => 'string']
                                            ]
                                        ]
                                    ]
                                ]
                            ]
                        ]
                    ]
                ],
                '/api/sql-injection/vulnerable' => [
                    'post' => [
                        'summary' => 'SQL Injection vulnerable endpoint',
                        'requestBody' => [
                            'content' => [
                                'application/json' => [
                                    'schema' => [
                                        'type' => 'object',
                                        'properties' => [
                                            'username' => ['type' => 'string'],
                                            'password' => ['type' => 'string']
                                        ]
                                    ]
                                ]
                            ]
                        ],
                        'responses' => [
                            '200' => [
                                'description' => 'Response from vulnerable endpoint',
                                'content' => [
                                    'application/json' => [
                                        'schema' => [
                                            'type' => 'object',
                                            'properties' => [
                                                'success' => ['type' => 'boolean'],
                                                'data' => ['type' => 'object'],
                                                'metadata' => ['type' => 'object']
                                            ]
                                        ]
                                    ]
                                ]
                            ]
                        ]
                    ]
                ],
                '/api/sql-injection/safe' => [
                    'post' => [
                        'summary' => 'SQL Injection safe endpoint',
                        'requestBody' => [
                            'content' => [
                                'application/json' => [
                                    'schema' => [
                                        'type' => 'object',
                                        'properties' => [
                                            'username' => ['type' => 'string'],
                                            'password' => ['type' => 'string']
                                        ]
                                    ]
                                ]
                            ]
                        ],
                        'responses' => [
                            '200' => [
                                'description' => 'Response from safe endpoint'
                            ]
                        ]
                    ]
                ],
                '/api/xss/vulnerable' => [
                    'post' => [
                        'summary' => 'XSS vulnerable endpoint',
                        'requestBody' => [
                            'content' => [
                                'application/json' => [
                                    'schema' => [
                                        'type' => 'object',
                                        'properties' => [
                                            'payload' => ['type' => 'string']
                                        ]
                                    ]
                                ]
                            ]
                        ],
                        'responses' => [
                            '200' => [
                                'description' => 'Response from XSS vulnerable endpoint'
                            ]
                        ]
                    ]
                ],
                '/api/xss/safe' => [
                    'post' => [
                        'summary' => 'XSS safe endpoint',
                        'requestBody' => [
                            'content' => [
                                'application/json' => [
                                    'schema' => [
                                        'type' => 'object',
                                        'properties' => [
                                            'payload' => ['type' => 'string']
                                        ]
                                    ]
                                ]
                            ]
                        ],
                        'responses' => [
                            '200' => [
                                'description' => 'Response from XSS safe endpoint'
                            ]
                        ]
                    ]
                ]
            ]
        ];

        header('Content-Type: application/json');
        return json_encode($swaggerJson, JSON_PRETTY_PRINT);
    }

    /**
     * Serve Swagger UI
     */
    public function serveSwaggerUI(): string
    {
        $swaggerJson = '/swagger.json';

        $html = '<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WebSec-Lab PHP API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3.25.0/swagger-ui.css" />
    <style>
        html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }
        *, *:before, *:after {
            box-sizing: inherit;
        }
        body {
            margin:0;
            background: #fafafa;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@3.25.0/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@3.25.0/swagger-ui-standalone-preset.js"></script>
    <script>
    window.onload = function() {
        const ui = SwaggerUIBundle({
            url: "' . $swaggerJson . '",
            dom_id: "#swagger-ui",
            deepLinking: true,
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIStandalonePreset
            ],
            plugins: [
                SwaggerUIBundle.plugins.DownloadUrl
            ],
            layout: "StandaloneLayout"
        });
    };
    </script>
</body>
</html>';

        return $html;
    }
}