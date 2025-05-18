#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#define LINE_SIZE 2048
#define MAX_LINES 5000
#define NUM_THREADS 4

// Global veri
char *lines[MAX_LINES];
int total_lines = 0;

// Thread ciktilari
typedef struct {
    int invalid_user;
    int failed_password;
    int auth_failure;
    int break_in;
} ThreadResult;

// Thread fonksiyonu
void *analyze_logs(void *arg) {
    int thread_id = *(int *)arg;
    int start = thread_id * (total_lines / NUM_THREADS);
    int end = (thread_id == NUM_THREADS - 1) ? total_lines : (start + (total_lines / NUM_THREADS));

    ThreadResult *result = malloc(sizeof(ThreadResult));
    result->invalid_user = 0;
    result->failed_password = 0;
    result->auth_failure = 0;
    result->break_in = 0;

    for (int i = start; i < end; i++) {
        char *content = strdup(lines[i]);  // satir kopyala
        char *token;
        char *rest = content;
        int col_index = 0;
        char content_field[1024] = "";

        while ((token = strtok_r(rest, ",", &rest))) {
            if (col_index == 6) {
                strncpy(content_field, token, sizeof(content_field) - 1);
                break;
            }
            col_index++;
        }

        if (strstr(content_field, "Invalid user")) result->invalid_user++;
        if (strstr(content_field, "Failed password")) result->failed_password++;
        if (strstr(content_field, "authentication failure")) result->auth_failure++;
        if (strstr(content_field, "POSSIBLE BREAK-IN ATTEMPT")) result->break_in++;

        free(content);
    }

    pthread_exit((void *)result);
}

// CSV'yi belleðe al
void load_csv(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Dosya acilmadi");
        exit(1);
    }

    char buffer[LINE_SIZE];
    fgets(buffer, LINE_SIZE, file); // basligi atla

    while (fgets(buffer, LINE_SIZE, file) && total_lines < MAX_LINES) {
        lines[total_lines] = strdup(buffer);  // satir bellege kopyalaniyor
        total_lines++;
    }

    fclose(file);
}

int main() {
    load_csv("openSSH_2k.log_structured.csv");

    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];

    clock_t start = clock();  // zaman baslat

    for (int i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        pthread_create(&threads[i], NULL, analyze_logs, &thread_ids[i]);
    }

    // Sonuclari topla
    ThreadResult final_result = {0, 0, 0, 0};
    for (int i = 0; i < NUM_THREADS; i++) {
        ThreadResult *thread_result;
        pthread_join(threads[i], (void **)&thread_result);

        final_result.invalid_user += thread_result->invalid_user;
        final_result.failed_password += thread_result->failed_password;
        final_result.auth_failure += thread_result->auth_failure;
        final_result.break_in += thread_result->break_in;

        free(thread_result);
    }

    clock_t end = clock();
    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;

    // Rapor
    printf("\n==== PARALLEL SSH LOG ANALYSIS ====\n");
    printf("Toplam log sayisi         : %d\n", total_lines);
    printf("Invalid user              : %d\n", final_result.invalid_user);
    printf("Failed password           : %d\n", final_result.failed_password);
    printf("Authentication failure    : %d\n", final_result.auth_failure);
    printf("Break-in attempt          : %d\n", final_result.break_in);
    printf("Analiz suresi (threaded)  : %.4f saniye\n", elapsed);

    // Hafiza temizligi
    for (int i = 0; i < total_lines; i++) {
        free(lines[i]);
    }

    return 0;
}
