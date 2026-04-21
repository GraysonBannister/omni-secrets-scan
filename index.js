const fs = require('fs/promises');
const path = require('path');
const { execSync } = require('child_process');

// Secret detection patterns
const SECRET_PATTERNS = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key', regex: /["'](aws|secret)[_\-]?(access)?[_\-]?(key|secret)?["']?\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']/gi },
  { name: 'GitHub Token', regex: /gh[pousr]_[a-zA-Z0-9]{36}/g },
  { name: 'GitHub OAuth', regex: /gho_[a-zA-Z0-9]{36}/g },
  { name: 'Slack Token', regex: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}(-[a-zA-Z0-9]{24})?/g },
  { name: 'Generic API Key', regex: /api[_\-]?key["']?\s*[:=]\s*["']?[a-zA-Z0-9_\-]{16,}["']/gi },
  { name: 'Private Key', regex: /-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { name: 'Password Assignment', regex: /password["']?\s*[:=]\s*["'][^"']{8,}["']/gi },
  { name: 'Secret Assignment', regex: /secret["']?\s*[:=]\s*["'][^"']{8,}["']/gi },
  { name: 'Bearer Token', regex: /bearer\s+[a-zA-Z0-9_\-\.]{20,}/gi },
  { name: 'JWT Token', regex: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g },
  { name: 'Stripe Key', regex: /sk_live_[0-9a-zA-Z]{24,}/g },
  { name: 'Basic Auth', regex: /basic\s+[a-zA-Z0-9=+/]{10,}/gi },
  { name: 'Connection String', regex: new RegExp('(mongodb|mysql|postgres|postgresql|redis|amqp)://[^:]+:[^@]+@', 'gi') },
];

async function findFiles(dir, excludePatterns) {
  const files = [];
  const entries = await fs.readdir(dir, { withFileTypes: true });
  
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    const relativePath = path.relative(process.cwd(), fullPath);
    
    // Check if path should be excluded
    let shouldExclude = false;
    for (const pattern of excludePatterns) {
      const regex = new RegExp(pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*'));
      if (regex.test(relativePath) || regex.test(entry.name)) {
        shouldExclude = true;
        break;
      }
    }
    if (shouldExclude) continue;
    
    if (entry.isDirectory()) {
      files.push(...await findFiles(fullPath, excludePatterns));
    } else {
      files.push(fullPath);
    }
  }
  
  return files;
}

module.exports = {
  name: "Omni Secrets Scan",
  version: "1.0.0",

  activate(context) {
    context.registerTool({
      name: "SecretsScan",
      description: "Scan code for hardcoded secrets, API keys, and credentials. Checks for AWS keys, GitHub tokens, private keys, and common password patterns.",
      permissionLevel: "safe",
      category: "read",
      
      inputSchema: {
        type: "object",
        properties: {
          path: { 
            type: "string", 
            description: "Directory or file to scan (default: cwd)" 
          },
          patterns: { 
            type: "array", 
            items: { type: "string" }, 
            description: "Specific patterns to check by name (default: all). Options: AWS Access Key, AWS Secret Key, GitHub Token, GitHub OAuth, Slack Token, Generic API Key, Private Key, Password Assignment, Secret Assignment, Bearer Token, JWT Token, Stripe Key, Basic Auth, Connection String" 
          },
          exclude: { 
            type: "array", 
            items: { type: "string" }, 
            description: "Glob patterns to exclude (e.g., node_modules, .git, dist)" 
          }
        }
      },

      validate(input) {
        if (input.patterns && !Array.isArray(input.patterns)) return "patterns must be an array";
        if (input.exclude && !Array.isArray(input.exclude)) return "exclude must be an array";
        return null;
      },

      async execute(input, toolContext) {
        const scanPath = input.path || toolContext.cwd;
        const excludeGlobs = input.exclude || ['node_modules', '.git', 'dist', 'build', '.next', '.nuxt'];
        
        // Filter patterns if specified
        let patternsToUse = SECRET_PATTERNS;
        if (input.patterns && input.patterns.length > 0) {
          patternsToUse = SECRET_PATTERNS.filter(p => input.patterns.includes(p.name));
          if (patternsToUse.length === 0) {
            return { content: `Error: No valid patterns selected. Available: ${SECRET_PATTERNS.map(p => p.name).join(', ')}`, isError: true };
          }
        }
        
        try {
          const absPath = path.isAbsolute(scanPath) ? scanPath : path.join(toolContext.cwd, scanPath);
          
          // Check if path exists
          try {
            await fs.access(absPath);
          } catch {
            return { content: `Error: Path not found: ${scanPath}`, isError: true };
          }
          
          // Determine if scanning a single file or directory
          const stat = await fs.stat(absPath);
          let files = [];
          
          if (stat.isFile()) {
            files = [absPath];
          } else {
            // Try git ls-files first for efficiency
            try {
              const output = execSync('git ls-files', { 
                cwd: toolContext.cwd, 
                encoding: 'utf-8',
                timeout: 10000
              });
              files = output.split('\n')
                .filter(f => f.trim())
                .map(f => path.join(toolContext.cwd, f));
            } catch {
              // Fallback: recursively find files
              files = await findFiles(absPath, excludeGlobs);
            }
          }

          const findings = [];
          const scannedFiles = [];
          
          for (const file of files) {
            // Skip binary files and excluded patterns
            const ext = path.extname(file).toLowerCase();
            const binaryExts = ['.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.tar', '.gz'];
            if (binaryExts.includes(ext)) continue;
            
            // Check exclusion patterns
            let shouldExclude = false;
            const relativePath = path.relative(toolContext.cwd, file);
            for (const pattern of excludeGlobs) {
              if (relativePath.includes(pattern) || file.includes(pattern)) {
                shouldExclude = true;
                break;
              }
            }
            if (shouldExclude) continue;
            
            scannedFiles.push(relativePath);
            
            try {
              const content = await fs.readFile(file, 'utf-8');
              const lines = content.split('\n');
              
              for (let i = 0; i < lines.length; i++) {
                for (const pattern of patternsToUse) {
                  const matches = lines[i].match(pattern.regex);
                  if (matches) {
                    matches.forEach(match => {
                      // Avoid duplicates for the same file/line/pattern
                      const isDuplicate = findings.some(f => 
                        f.file === relativePath && 
                        f.line === i + 1 && 
                        f.pattern === pattern.name
                      );
                      if (!isDuplicate) {
                        findings.push({
                          file: relativePath,
                          line: i + 1,
                          pattern: pattern.name,
                          match: match.substring(0, 40) + (match.length > 40 ? '...' : ''),
                          preview: lines[i].trim().substring(0, 80) + (lines[i].length > 80 ? '...' : '')
                        });
                      }
                    });
                  }
                }
              }
            } catch (err) {
              // Skip unreadable files
            }
          }

          if (findings.length === 0) {
            return { 
              content: `✅ No secrets or credentials found in ${scannedFiles.length} scanned file(s).`,
              metadata: { scannedFiles: scannedFiles.length, findings: 0 }
            };
          }

          // Sort by file then line
          findings.sort((a, b) => {
            if (a.file !== b.file) return a.file.localeCompare(b.file);
            return a.line - b.line;
          });

          // Format as markdown table
          let output = `## ⚠️ Secrets Scan Results\n\n`;
          output += `**Scanned:** ${scannedFiles.length} files\n`;
          output += `**Findings:** ${findings.length} potential secret(s)\n\n`;
          output += "| File | Line | Pattern | Match |\n";
          output += "|------|------|---------|-------|\n";
          
          for (const f of findings) {
            output += `| \`${f.file}\` | ${f.line} | ${f.pattern} | \`${f.match}\` |\n`;
          }
          
          output += "\n---\n\n**Important Notes:**\n";
          output += "- Review each finding carefully - some matches may be false positives\n";
          output += "- Example values, test data, or placeholder strings can trigger matches\n";
          output += "- Environment variable references (e.g., `process.env.SECRET`) are safe\n";
          
          return { 
            content: output, 
            metadata: { 
              scannedFiles: scannedFiles.length, 
              findings: findings.length,
              matches: findings 
            } 
          };
        } catch (error) {
          return { content: `Error scanning: ${error.message}`, isError: true };
        }
      }
    });
  },

  deactivate() {}
};
