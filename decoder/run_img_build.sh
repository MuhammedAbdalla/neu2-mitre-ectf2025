# To rebuild images quickly
docker rmi decoder

docker build -t decoder .

echo "$(realpath ./build_out):/out"
echo "$(realpath ./decoder_out):/decoder"
echo "$(realpath ../secrets):/secrets" \

docker run \
    --rm \
    -v "$(realpath ./build_out):/out" \
    -v "$(realpath ./):/decoder" \
    -v "$(realpath ../secrets):/secrets" \
    -e DECODER_ID="0xdeadbeef" \
    decoder