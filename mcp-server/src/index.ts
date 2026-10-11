import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { spawn } from "child_process";
import * as path from "path";

// WhatsApp IP Hunter project path
const PROJECT_ROOT = "E:\\whatsup_now";
const PYTHON_PATH = "E:\\whatsup_now\\.venv\\Scripts\\python.exe";

// Tool input schemas
const HuntIPSchema = z.object({
  phone_number: z.string().describe("Target phone number in international format (e.g., +1234567890)"),
  capture_time: z.number().optional().default(5).describe("Capture duration in seconds"),
  interface: z.string().optional().describe("Network interface to use"),
  headless: z.boolean().optional().default(true).describe("Run browser in headless mode"),
});

const BulkHuntSchema = z.object({
  phone_numbers: z.array(z.string()).describe("Array of target phone numbers"),
  capture_time: z.number().optional().default(3).describe("Capture duration per target"),
  interface: z.string().optional().describe("Network interface to use"),
});

const ContinuousModeSchema = z.object({
  phone_file: z.string().describe("Path to file containing phone numbers (one per line)"),
  capture_time: z.number().optional().default(2).describe("Capture duration per target"),
  interface: z.string().optional().describe("Network interface to use"),
});

const ListInterfacesSchema = z.object({});

const GeoLookupSchema = z.object({
  ips: z.array(z.string()).describe("Array of IP addresses to geolocate"),
});

// Helper function to run Python CLI commands
async function runPythonCommand(args: string[]): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const child = spawn(PYTHON_PATH, ["src/cli.py", ...args], {
      cwd: PROJECT_ROOT,
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    child.stdout?.on("data", (data) => {
      stdout += data.toString();
    });

    child.stderr?.on("data", (data) => {
      stderr += data.toString();
    });

    child.on("close", (exitCode) => {
      resolve({ stdout, stderr, exitCode: exitCode ?? 0 });
    });

    child.on("error", (error) => {
      resolve({ stdout, stderr: error.message, exitCode: 1 });
    });

    // Timeout after 120 seconds
    setTimeout(() => {
      child.kill("SIGTERM");
      resolve({ stdout, stderr: "Process timed out after 120 seconds", exitCode: 124 });
    }, 120000);
  });
}

// Create the MCP server
const server = new Server(
  {
    name: "whatsapp-ip-hunter",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "hunt_ip",
        description: "Hunt a single target's IP address via WhatsApp call initiation. Triggers STUN packet exchange during call ringing phase to extract target's public IP and geolocate it.",
        inputSchema: {
          type: "object",
          properties: {
            phone_number: {
              type: "string",
              description: "Target phone number in international format (e.g., +1234567890)",
            },
            capture_time: {
              type: "number",
              description: "Capture duration in seconds",
              default: 5,
            },
            interface: {
              type: "string",
              description: "Network interface to use (optional, auto-detected if not specified)",
            },
            headless: {
              type: "boolean",
              description: "Run browser in headless mode",
              default: true,
            },
          },
          required: ["phone_number"],
        },
      },
      {
        name: "bulk_hunt",
        description: "Hunt multiple targets' IP addresses simultaneously. Initiates parallel WhatsApp calls and captures STUN packets for each target.",
        inputSchema: {
          type: "object",
          properties: {
            phone_numbers: {
              type: "array",
              items: { type: "string" },
              description: "Array of target phone numbers in international format",
            },
            capture_time: {
              type: "number",
              description: "Capture duration per target in seconds",
              default: 3,
            },
            interface: {
              type: "string",
              description: "Network interface to use",
            },
          },
          required: ["phone_numbers"],
        },
      },
      {
        name: "continuous_mode",
        description: "Continuous IP hunting from a file containing phone numbers. Processes each number sequentially with minimal delay.",
        inputSchema: {
          type: "object",
          properties: {
            phone_file: {
              type: "string",
              description: "Path to file containing phone numbers (one per line)",
            },
            capture_time: {
              type: "number",
              description: "Capture duration per target in seconds",
              default: 2,
            },
            interface: {
              type: "string",
              description: "Network interface to use",
            },
          },
          required: ["phone_file"],
        },
      },
      {
        name: "list_interfaces",
        description: "List available network interfaces for packet capture. Shows interface names and IP addresses.",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
      {
        name: "geolocate_ips",
        description: "Perform geolocation lookup on IP addresses using MaxMind Precision API and fallback services. Returns country, region, city, coordinates, ASN, and organization.",
        inputSchema: {
          type: "object",
          properties: {
            ips: {
              type: "array",
              items: { type: "string" },
              description: "Array of IP addresses to geolocate",
            },
          },
          required: ["ips"],
        },
      },
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "hunt_ip": {
        const params = HuntIPSchema.parse(args);
        const cliArgs = [
          "hunt",
          params.phone_number,
          "--seconds", params.capture_time.toString(),
        ];
        if (params.interface) {
          cliArgs.push("--interface", params.interface);
        }
        if (!params.headless) {
          cliArgs.push("--no-head");
        }

        const result = await runPythonCommand(cliArgs);
        return {
          content: [
            {
              type: "text",
              text: result.stdout || result.stderr,
            },
          ],
          isError: result.exitCode !== 0,
        };
      }

      case "bulk_hunt": {
        const params = BulkHuntSchema.parse(args);
        const cliArgs = [
          "bulk-hunt",
          ...params.phone_numbers,
          "--seconds", params.capture_time.toString(),
        ];
        if (params.interface) {
          cliArgs.push("--interface", params.interface);
        }

        const result = await runPythonCommand(cliArgs);
        return {
          content: [
            {
              type: "text",
              text: result.stdout || result.stderr,
            },
          ],
          isError: result.exitCode !== 0,
        };
      }

      case "continuous_mode": {
        const params = ContinuousModeSchema.parse(args);
        const cliArgs = [
          "continuous-mode",
          params.phone_file,
          "--seconds", params.capture_time.toString(),
        ];
        if (params.interface) {
          cliArgs.push("--interface", params.interface);
        }

        const result = await runPythonCommand(cliArgs);
        return {
          content: [
            {
              type: "text",
              text: result.stdout || result.stderr,
            },
          ],
          isError: result.exitCode !== 0,
        };
      }

      case "list_interfaces": {
        const result = await runPythonCommand(["interfaces"]);
        return {
          content: [
            {
              type: "text",
              text: result.stdout || result.stderr,
            },
          ],
          isError: result.exitCode !== 0,
        };
      }

      case "geolocate_ips": {
        const params = GeoLookupSchema.parse(args);
        // Use the geolocation module directly
        const cliArgs = [
          "-c",
          `
import asyncio
import sys
sys.path.insert(0, r"${PROJECT_ROOT}")
from src.geolocation import GeoLocationService

async def main():
    service = GeoLocationService()
    results = await service.lookup_bulk(${JSON.stringify(params.ips)})
    for ip, data in results.items():
        print(f"{ip}: {data.get('country', 'Unknown')}, {data.get('city', 'Unknown')}, {data.get('source', 'unknown')}")
        if data.get('latitude') and data.get('longitude'):
            print(f"  Coordinates: {data['latitude']}, {data['longitude']}")
        if data.get('asn'):
            print(f"  ASN: {data['asn']}")
        if data.get('organization'):
            print(f"  Org: {data['organization']}")

asyncio.run(main())
        `,
        ];

        const result = await runPythonCommand(cliArgs);
        return {
          content: [
            {
              type: "text",
              text: result.stdout || result.stderr,
            },
          ],
          isError: result.exitCode !== 0,
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    return {
      content: [
        {
          type: "text",
          text: `Error: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("WhatsApp IP Hunter MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Server error:", error);
  process.exit(1);
});