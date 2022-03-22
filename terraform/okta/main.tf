terraform {
  required_providers {
    okta = {
      source  = "okta/okta"
      version = "3.22.1"
    }
  }
}

provider "okta" {
  org_name  = var.org_name
  base_url  = "okta.com"
  api_token = var.api_token
}

resource "okta_app_oauth" "example" {
  label          = "example"
  type           = "web"
  grant_types    = ["authorization_code", "implicit"]
  redirect_uris  = [var.redirect_uri]
  response_types = ["code", "id_token"]
}

data "okta_group" "everyone" {
  name = "Everyone"
}

resource "okta_app_group_assignment" "example" {
  app_id   = okta_app_oauth.example.id
  group_id = data.okta_group.everyone.id
}