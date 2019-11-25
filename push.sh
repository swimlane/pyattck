#!/bin/sh

setup_git() {
  git config --global user.email "joshswimlane@swimlane.com"
  git config --global user.name "Travis CI"
}

commit_website_files() {
  git checkout -b master
  git add . generated_attck_data.json
  git commit --message "Travis build: $TRAVIS_BUILD_NUMBER"
}

upload_files() {
  git remote add origin-pages https://${GH_TOKEN}@github.com/swimlane/pyattck.git > /dev/null 2>&1
  git push origin master --quiet 
}

setup_git
commit_website_files
upload_files