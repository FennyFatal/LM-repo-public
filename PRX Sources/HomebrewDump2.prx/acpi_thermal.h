struct acpi_tz_softc {
    void *tz_dev;
    void *tz_handle;	/*Thermal zone handle*/
    int	  tz_temperature;	/*Current temperature*/
    int	  tz_active;	/*Current active cooling*/
    int	  tz_requested;	/*Minimum active cooling*/
    int	  tz_thflags;	/*Current temp-related flags*/
    int	  tz_flags;
    void *tz_cooling_started;
    void *tz_sysctl_ctx;
    void *tz_sysctl_tree;
    void *tz_event;

    void *tz_zone;	/*Thermal zone parameters*/
    int	  tz_validchecks;
    int	  tz_insane_tmp_notified;

    /* passive cooling */
    void *tz_cooling_proc;
    int	  tz_cooling_proc_running;
    int	  tz_cooling_enabled;
    int	  tz_cooling_active;
    int	  tz_cooling_updated;
    int	  tz_cooling_saved_freq;
};