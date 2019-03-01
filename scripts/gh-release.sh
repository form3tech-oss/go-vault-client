#!/usr/bin/env bash

if git describe --exact-match;  then
    TAG="$(git describe --exact-match)"
    NAME="$TAG"
    BODY="release $TAG"
    REPO="form3tech/sepainstant-gateway"
    FILE="$(git rev-parse --show-toplevel)/swagger.yaml"

    payload=$(
      jq --null-input \
         --arg tag "$TAG" \
         --arg name "$NAME" \
         --arg body "$BODY" \
         '{ tag_name: $tag, name: $name, body: $body, draft: false }'
    )

    response=$(
      curl -d "$payload" \
           "https://api.github.com/repos/form3tech/sepainstant-gateway/releases?access_token=$GITHUB_TOKEN"
    )

    upload_url="$(echo "$response" | jq -r .upload_url | sed -e "s/{?name,label}//")"

    curl -H "Content-Type:application/yml" \
         --data-binary "@$FILE" \
           "$upload_url?name=$(basename "$FILE")&access_token=$GITHUB_TOKEN"
fi
