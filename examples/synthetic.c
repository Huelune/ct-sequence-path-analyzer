/* Entirely synthetic; normalized C subset, no customer source. */
void Target(void) { }
void Fallback(void) { }
void Producer(void) {
    Rte_Write_Status(3);
}
void Consumer(void) {
    int status;
    Rte_Read_Status(&status);
    if (status == 1) {
        Fallback();
    } else if (status == 2) {
        Fallback();
    } else {
        Target();
    }
}
void Harness(void) {
    Producer();
    Consumer();
}
