#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

/**
 * Faz 15 - Plan B Launcher: LD_PRELOAD Stealth Injector
 * Bu arac, Matrix Hook C-Constructor'unu (matrix_hook.so) hedefe mermi gibi yukler.
 * Kullanm: ./svm_run <binary_path> [argümanlar...]
 */
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("\033[31m[!] Kullanım: %s <binary_path> [argümanlar...]\033[0m\n", argv[0]);
        return 1;
    }

    char hook_path[PATH_MAX];
    // Matrix hook modulu, bu aracla ayni dizindeki 'matrix_hook.so' olarak beklenmektedir.
    // Ancak guvenli olmasi acisindan tam yolunu (Absolute Path) aliyoruz:
    if (realpath("./matrix_hook.so", hook_path) == NULL) {
        printf("\033[31m[!] HATA: matrix_hook.so bulunamadi. (Makefile compile ettiniz mi?)\033[0m\n");
        return 1;
    }

    // Hedef surece, kendi bellek diske cikarilmadan once bizim library'mizi yukletiyoruz.
    // Execvp sonrasinda bizim '_init' kodumuz calisacak.
    setenv("LD_PRELOAD", hook_path, 1);
    
    printf("\033[36m[*] Loader: %s LD_PRELOAD=%s ile Matrix'e firlatiliyor...\033[0m\n", argv[1], hook_path);

    // Asil hedef calistirilir. (Process Görüntüsü Yıkılır ve Yerine Hedef Geçer)
    execvp(argv[1], &argv[1]);
    
    // Sadece hata durumunda buraya duser
    perror("\033[31m[!] execvp basarisiz\033[0m");
    return 1;
}
