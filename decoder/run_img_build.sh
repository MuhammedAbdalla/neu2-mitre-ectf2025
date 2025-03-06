# To rebuild images quickly
docker rmi decoder

echo "$(realpath ./build_out):/out"
echo "$(realpath ./decoder_out):/decoder"
echo "$(realpath ../secrets/global.secrets):/global.secrets" \

docker build -t decoder .

docker run \
    --rm \
    -v "$(realpath ./build_out):/out" \
    -v "$(realpath ./):/decoder" \
    -v "$(realpath ../secrets/global.secrets):/global.secrets:ro" \
    -e DECODER_ID="0xdeadbeef" \
    decoder


