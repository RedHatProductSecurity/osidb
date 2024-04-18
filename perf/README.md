# Performance tests

This directory contains a set of standalone [locust](https://docs.locust.io/en/stable/) locust perf tests.

To independently run locust perf tests, first install locust and then run in headless mode:
```shell
> pip install locust
> locust --headless -f ./perf --host https://$OSIDB_HOST --users 5 --spawn-rate 2 --csv=locust-result.csv --run-time 1m
```

To invoke locust web ux setting the target host and which tests to run (ex. _CoreUser_)
```shell
> pip install locust
> locust --class-picker -f ./perf -H http://$OSIDB_HOST --web-host 0.0.0.0:9000  --modern-ui
```