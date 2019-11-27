#!/bin/sh

setup_git() {
  git config --global user.email "45767933+joshswimlane@users.noreply.github.com"
  git config --global user.name "joshswimlane"
}

commit_website_files() {
  git checkout -b master
  git add . generated_attck_data.json
  git commit --message "Travis build: $TRAVIS_BUILD_NUMBER"
}

upload_files() {
  git push origin master --quiet 
}

setup_git
commit_website_files
upload_files