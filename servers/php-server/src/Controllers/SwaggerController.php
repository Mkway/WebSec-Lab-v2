<?php

namespace WebSecLab\Controllers;

use OpenApi\Generator;

class SwaggerController
{
    /**
     * Generate Swagger JSON documentation
     */
    public function generateSwaggerJson(): string
    {
        $openapi = Generator::scan([__DIR__ . '/../']);

        header('Content-Type: application/json');
        return $openapi->toJson();
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