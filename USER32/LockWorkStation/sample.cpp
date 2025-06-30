#include <windows.h>
#include <thread>
#include <chrono>
#include <iostream>

void changeWallpaperToCyan() {
    // Wait to ensure the lock screen is active
    std::this_thread::sleep_for(std::chrono::seconds(5));

    HKEY hKey;

    // Step 1: Set solid background color (R=0, G=255, B=255 -> Cyan)
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Control Panel\\Colors", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        const char* cyanRGB = "0 255 255";
        RegSetValueExA(hKey, "Background", 0, REG_SZ, reinterpret_cast<const BYTE*>(cyanRGB), strlen(cyanRGB));
        RegCloseKey(hKey);
        std::cout << "[+] Background color set to cyan.\n";
    } else {
        std::cerr << "[-] Failed to set background color.\n";
    }

    // Step 2: Disable image wallpaper and use solid color
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Control Panel\\Desktop", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        const char* empty = "";
        const char* style = "0";  // 0 = Center (doesn't matter for solid)
        const char* tile = "0";   // No tiling

        RegSetValueExA(hKey, "Wallpaper", 0, REG_SZ, reinterpret_cast<const BYTE*>(empty), strlen(empty));
        RegSetValueExA(hKey, "WallpaperStyle", 0, REG_SZ, reinterpret_cast<const BYTE*>(style), strlen(style));
        RegSetValueExA(hKey, "TileWallpaper", 0, REG_SZ, reinterpret_cast<const BYTE*>(tile), strlen(tile));

        RegCloseKey(hKey);
        std::cout << "[+] Wallpaper disabled. Solid color will be used.\n";

        // Apply the changes
        SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, NULL, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
    } else {
        std::cerr << "[-] Failed to update wallpaper settings.\n";
    }
}

int main() {
    // Run background thread to change wallpaper
    std::thread worker(changeWallpaperToCyan);

    // Lock workstation
    if (!LockWorkStation()) {
        std::cerr << "[-] Failed to lock workstation.\n";
    }

    worker.join();
    return 0;
}
