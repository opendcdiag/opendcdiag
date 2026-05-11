## Modernization instructions

The codebase has existed for many years and coding conventions have evolved over time. 

Legacy conventions are generally not against coding style.
However there is some value in modernizing the existing codebase.

Consider providing suggestions, at "none" severity, when encountering legacy
constructs to modernize the code under review.


### test_time_condition to TEST_LOOP conversion

Legacy pattern:
```
    do {
         ... test content ...
    } while (test_time_condition(test));
```
Modernized pattern:
```
    TEST_LOOP(test, 1) {
        ... test content ...
    }
```


### advanced test_time_condition to TEST_LOOP conversion

Legacy pattern:
```
    do {
        for (int i = 0; i < 1024; i++)
            ... test content ...
    } while (test_time_condition(test));
```
Modernized pattern:
```
    TEST_LOOP(test, 1024) {
        ... test content ...
    }
```


### log_error + report_fail to report_fail_msg conversion

Legacy pattern:
```
    log_error("ERROR MESSAGE\n");
    report_fail(test);
```

Modernized pattern:
```
    report_fail_msg("ERROR_MESSAGE");
```

Ensure to remove the newline from the string as report_fail_msg() will add
this internally.

