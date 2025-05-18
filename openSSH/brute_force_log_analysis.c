#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LINE_SIZE 2048

int main() {
    FILE *file = fopen("openSSH_2k.log_structured.csv", "r");
    if (!file) {
        perror("File open failed");
        return 1;
    }

    // Sayaclar
    int total_logs = 0;
    int count_invalid_user = 0;
    int count_failed_password = 0;
    int count_auth_failure = 0;
    int count_break_in = 0;
    int count_disconnect = 0;
    int count_conn_closed = 0;
    int count_no_id_string = 0;
    int count_too_many_failures = 0;

    char line[LINE_SIZE];

    // Zamani baslat
    clock_t start_time = clock();

    // Basliklari atla
    fgets(line, sizeof(line), file);

    while (fgets(line, sizeof(line), file)) {
        total_logs++;

        // Content sutunu 7. alan (index 6)
        char *token;
        char *rest = line;
        int col_index = 0;
        char content[1024] = "";

        while ((token = strtok_r(rest, ",", &rest))) {
            if (col_index == 6) {
                strncpy(content, token, sizeof(content) - 1);
                break;
            }
            col_index++;
        }

        // Içerik analizleri
        if (strstr(content, "Invalid user")) count_invalid_user++;
        if (strstr(content, "Failed password")) count_failed_password++;
        if (strstr(content, "authentication failure")) count_auth_failure++;
        if (strstr(content, "POSSIBLE BREAK-IN ATTEMPT")) count_break_in++;
        if (strstr(content, "disconnect")) count_disconnect++;
        if (strstr(content, "Connection closed")) count_conn_closed++;
        if (strstr(content, "Did not receive identification")) count_no_id_string++;
        if (strstr(content, "Too many authentication failures")) count_too_many_failures++;
    }

    clock_t end_time = clock();
    double duration = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    // Raporlama
    printf("\n==== SSH LOG ANALYSIS ====\n");
    printf("Toplam log sayisi           : %d\n", total_logs);
    printf("Invalid user girisimi       : %d\n", count_invalid_user);
    printf("Failed password girisimi    : %d\n", count_failed_password);
    printf("Auth failure hatasi         : %d\n", count_auth_failure);
    printf("Break-in uyarisi            : %d\n", count_break_in);
    printf("Disconnect mesaji          : %d\n", count_disconnect);
    printf("Connection closed mesaji    : %d\n", count_conn_closed);
    printf("No ID string durumu         : %d\n", count_no_id_string);
    printf("Too many failures uyarisi   : %d\n", count_too_many_failures);
    printf("Analiz suresi               : %.4f saniye\n", duration);

    fclose(file);
    return 0;
}
