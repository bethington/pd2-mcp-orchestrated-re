// Basic Frida hooks for common API calls
console.log("Loading basic hooks...");

// Hook CreateFileA
if (Module.findExportByName("kernel32.dll", "CreateFileA")) {
    Interceptor.attach(Module.findExportByName("kernel32.dll", "CreateFileA"), {
        onEnter: function(args) {
            console.log("CreateFileA called with filename: " + args[0].readAnsiString());
        }
    });
}

// Hook WriteFile
if (Module.findExportByName("kernel32.dll", "WriteFile")) {
    Interceptor.attach(Module.findExportByName("kernel32.dll", "WriteFile"), {
        onEnter: function(args) {
            console.log("WriteFile called");
        }
    });
}

console.log("Basic hooks loaded successfully");