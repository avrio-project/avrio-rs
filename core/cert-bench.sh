while :
do
    cargo test --quiet --release --package avrio_core --lib -- certificate::tests::test_cert_diff --exact --nocapture 2>/dev/null
done