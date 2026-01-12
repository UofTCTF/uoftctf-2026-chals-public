import binaryen from 'binaryen';

export default function transformWasm(wasmBuffer, config) {
  
  const wmod = binaryen.readBinary(wasmBuffer);
  const ALL = 0xFFFFFFFF;
  // Disable CustomDescriptors
  wmod.setFeatures(ALL ^ (1 << 21));
  
  const wasmText = wmod.emitText();
  wmod.dispose();
  
  // Generate hook imports for all instruction configurations
  const hookImports = [];
  const replacements = [];
  
  for (const [instruction, [params, results]] of Object.entries(config)) {
    // const hookName = instruction.replaceAll('.', '_');
    const paramStr = params.length ? `(param ${params.join(' ')})` : '';
    const resultStr = results.length ? `(result ${results.join(' ')})` : '';
    
    const funcName = `$hook.${instruction}`;
    const hookImport = `(import "hook" "${instruction}" (func ${funcName} ${paramStr} ${resultStr}))`;

    hookImports.push(hookImport);
    
    // Create regex to replace the instruction with the hook call
    const instrRegex = new RegExp(`\\b${instruction.replace('.', '\\.')}\\b`, 'g');
    replacements.push({
      pattern: instrRegex,
      replacement: `call ${funcName}`,
    });
  }

  let transformedText = wasmText;
  
  // Apply all replacements
  for (const { pattern, replacement } of replacements) {
    transformedText = transformedText.replace(pattern, replacement);
  }

  const lines = transformedText.split('\n');
  const moduleIndex = lines.findIndex(line => line.trim().startsWith('(module'));
  
  // Insert all hook imports after module declaration
  if (moduleIndex !== -1) {
    lines.splice(moduleIndex + 1, 0, ...hookImports);
  }
  
  transformedText = lines.join('\n');

  const finalMod = binaryen.parseText(transformedText);
  finalMod.setFeatures(0xFFFFFFFF);
  finalMod.setFeatures(ALL ^ (1 << 21));
  const outputBuffer = finalMod.emitBinary();
  finalMod.dispose();

  return outputBuffer;
}
