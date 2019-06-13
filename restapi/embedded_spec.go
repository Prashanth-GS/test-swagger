// Code generated by go-swagger; DO NOT EDIT.

package restapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
)

var (
	// SwaggerJSON embedded version of the swagger document used at generation time
	SwaggerJSON json.RawMessage
	// FlatSwaggerJSON embedded flattened version of the swagger document used at generation time
	FlatSwaggerJSON json.RawMessage
)

func init() {
	SwaggerJSON = json.RawMessage([]byte(`{
  "consumes": [
    "application/json"
  ],
  "produces": [
    "application/json"
  ],
  "schemes": [
    "http"
  ],
  "swagger": "2.0",
  "info": {
    "description": "Authentication Service API",
    "title": "Auth Service",
    "contact": {
      "name": "NEWS API Support"
    },
    "version": "1.0.0"
  },
  "basePath": "/news-api/v1",
  "paths": {
    "/login": {
      "$ref": "./paths/login.yml"
    },
    "/refresh-token": {
      "$ref": "./paths/refreshToken.yml"
    },
    "/register": {
      "$ref": "./paths/register.yml"
    },
    "/register-confirmation/{token}": {
      "$ref": "./paths/registerConfirmation.yml"
    },
    "/register-details": {
      "$ref": "./paths/registerDetails.yml"
    },
    "/reset-password": {
      "$ref": "./paths/resetPassword.yml"
    },
    "/reset-password-confirmation/{token}": {
      "$ref": "./paths/resetPasswordConf.yml"
    },
    "/reset-password-request/{email}": {
      "$ref": "./paths/resetPasswordReq.yml"
    }
  },
  "definitions": {
    "generalResponse": {
      "$ref": "./definitions/generalResponse.yml"
    },
    "loginResponse": {
      "$ref": "./definitions/loginResponse.yml"
    }
  }
}`))
	FlatSwaggerJSON = json.RawMessage([]byte(`{
  "consumes": [
    "application/json"
  ],
  "produces": [
    "application/json"
  ],
  "schemes": [
    "http"
  ],
  "swagger": "2.0",
  "info": {
    "description": "Authentication Service API",
    "title": "Auth Service",
    "contact": {
      "name": "NEWS API Support"
    },
    "version": "1.0.0"
  },
  "basePath": "/news-api/v1",
  "paths": {
    "/login": {
      "post": {
        "tags": [
          "login"
        ],
        "parameters": [
          {
            "name": "loginRequest",
            "in": "body",
            "schema": {
              "$ref": "#/definitions/loginRequest"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "$ref": "#/definitions/loginResponse"
            }
          },
          "400": {
            "description": "BAD REQUEST",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "401": {
            "description": "UNAUTHORIZED",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "403": {
            "description": "FORBIDDEN",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "404": {
            "description": "NOT FOUND",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "500": {
            "description": "INTERNAL SERVER ERROR",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          }
        }
      }
    },
    "/refresh-token": {
      "get": {
        "tags": [
          "login"
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "$ref": "#/definitions/loginResponse"
            }
          },
          "400": {
            "description": "BAD REQUEST",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "401": {
            "description": "UNAUTHORIZED",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "403": {
            "description": "FORBIDDEN",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "404": {
            "description": "NOT FOUND",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "500": {
            "description": "INTERNAL SERVER ERROR",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          }
        }
      }
    },
    "/register": {
      "post": {
        "tags": [
          "register"
        ],
        "parameters": [
          {
            "name": "registerRequest",
            "in": "body",
            "schema": {
              "$ref": "#/definitions/registerRequest"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "400": {
            "description": "BAD REQUEST",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "401": {
            "description": "UNAUTHORIZED",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "403": {
            "description": "FORBIDDEN",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "404": {
            "description": "NOT FOUND",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "500": {
            "description": "INTERNAL SERVER ERROR",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          }
        }
      }
    },
    "/register-confirmation/{token}": {
      "get": {
        "tags": [
          "register"
        ],
        "parameters": [
          {
            "type": "string",
            "name": "token",
            "in": "path",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "400": {
            "description": "BAD REQUEST",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "401": {
            "description": "UNAUTHORIZED",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "403": {
            "description": "FORBIDDEN",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "404": {
            "description": "NOT FOUND",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "500": {
            "description": "INTERNAL SERVER ERROR",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          }
        }
      }
    },
    "/register-details": {
      "post": {
        "tags": [
          "register"
        ],
        "parameters": [
          {
            "name": "registerRequest",
            "in": "body",
            "schema": {
              "$ref": "#/definitions/registerDetailsRequest"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "400": {
            "description": "BAD REQUEST",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "401": {
            "description": "UNAUTHORIZED",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "403": {
            "description": "FORBIDDEN",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "404": {
            "description": "NOT FOUND",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "500": {
            "description": "INTERNAL SERVER ERROR",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          }
        }
      }
    },
    "/reset-password": {
      "post": {
        "tags": [
          "login"
        ],
        "parameters": [
          {
            "name": "passwordRequest",
            "in": "body",
            "schema": {
              "$ref": "#/definitions/passwordRequest"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "400": {
            "description": "BAD REQUEST",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "401": {
            "description": "UNAUTHORIZED",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "403": {
            "description": "FORBIDDEN",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "404": {
            "description": "NOT FOUND",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "500": {
            "description": "INTERNAL SERVER ERROR",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          }
        }
      }
    },
    "/reset-password-confirmation/{token}": {
      "get": {
        "tags": [
          "login"
        ],
        "parameters": [
          {
            "type": "string",
            "name": "token",
            "in": "path",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "$ref": "#/definitions/userEmailResponse"
            }
          },
          "400": {
            "description": "BAD REQUEST",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "401": {
            "description": "UNAUTHORIZED",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "403": {
            "description": "FORBIDDEN",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "404": {
            "description": "NOT FOUND",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "500": {
            "description": "INTERNAL SERVER ERROR",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          }
        }
      }
    },
    "/reset-password-request/{email}": {
      "get": {
        "tags": [
          "login"
        ],
        "parameters": [
          {
            "type": "string",
            "name": "email",
            "in": "path",
            "required": true
          }
        ],
        "responses": {
          "200": {
            "description": "OK",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "400": {
            "description": "BAD REQUEST",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "401": {
            "description": "UNAUTHORIZED",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "403": {
            "description": "FORBIDDEN",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "404": {
            "description": "NOT FOUND",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          },
          "500": {
            "description": "INTERNAL SERVER ERROR",
            "schema": {
              "$ref": "#/definitions/generalResponse"
            }
          }
        }
      }
    }
  },
  "definitions": {
    "generalResponse": {
      "type": "object",
      "properties": {
        "error": {
          "properties": {
            "code": {
              "code": "int"
            },
            "message": {
              "message": "string"
            }
          },
          "error": "object"
        },
        "message": {
          "message": "string"
        },
        "success": {
          "success": "boolean"
        }
      }
    },
    "loginRequest": {
      "type": "object",
      "properties": {
        "email": {
          "email": "string"
        },
        "password": {
          "password": "string"
        },
        "type": {
          "type": "string"
        }
      }
    },
    "loginResponse": {
      "type": "object",
      "properties": {
        "data": {
          "properties": {
            "accessToken": {
              "accessToken": "string"
            },
            "expiresIn": {
              "expiresIn": "string"
            }
          },
          "response": "object"
        },
        "error": {
          "properties": {
            "code": {
              "code": "int"
            },
            "message": {
              "message": "string"
            }
          },
          "error": "object"
        },
        "success": {
          "success": "boolean"
        }
      }
    },
    "passwordRequest": {
      "type": "object",
      "properties": {
        "email": {
          "email": "string"
        },
        "password": {
          "password": "string"
        }
      }
    },
    "registerDetailsRequest": {
      "type": "object",
      "properties": {
        "designation": {
          "designation": "string"
        },
        "email": {
          "email": "string"
        },
        "employeeCount": {
          "employeeCount": "int"
        },
        "organization": {
          "organization": "string"
        }
      }
    },
    "registerRequest": {
      "type": "object",
      "properties": {
        "email": {
          "email": "string"
        },
        "password": {
          "password": "string"
        },
        "type": {
          "type": "string"
        }
      }
    },
    "userEmailResponse": {
      "type": "object",
      "properties": {
        "data": {
          "properties": {
            "email": {
              "email": "string"
            },
            "message": {
              "message": "string"
            }
          },
          "response": "object"
        },
        "error": {
          "properties": {
            "code": {
              "code": "int"
            },
            "message": {
              "message": "string"
            }
          },
          "error": "object"
        },
        "success": {
          "success": "boolean"
        }
      }
    }
  }
}`))
}
