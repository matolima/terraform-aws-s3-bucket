data "aws_region" "current" {}

data "aws_canonical_user_id" "this" {}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}
locals {
  create_bucket = var.create_bucket && var.putin_khuylo

  attach_policy = var.attach_require_latest_tls_policy || var.attach_elb_log_delivery_policy || var.attach_lb_log_delivery_policy || var.attach_deny_insecure_transport_policy || var.attach_inventory_destination_policy || var.attach_policy

  # Variables with type `any` should be jsonencode()'d when value is coming from Terragrunt
  grants               = try(jsondecode(var.grant), var.grant)
  cors_rules           = try(jsondecode(var.cors_rule), var.cors_rule)
  lifecycle_rules      = try(jsondecode(var.lifecycle_rule), var.lifecycle_rule)
  intelligent_tiering  = try(jsondecode(var.intelligent_tiering), var.intelligent_tiering)
  metric_configuration = try(jsondecode(var.metric_configuration), var.metric_configuration)
}

resource "aws_s3_bucket" "this" {
  count = local.create_bucket ? 1 : 0

  bucket        = var.bucket
  #bucket_prefix = var.bucket_prefix

  force_destroy       = var.force_destroy
  object_lock_enabled = var.object_lock_enabled
  tags                = var.tags
  
}


resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.this[0].id

  rule {
    id     = "Incomplete multi-part uploads"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 8
    }
  }
  depends_on = [aws_s3_bucket.this]
}


resource "aws_s3_bucket_policy" "this" {
  count = local.create_bucket && local.attach_policy ? 1 : 0

  bucket = aws_s3_bucket.this[0].id
  policy = data.aws_iam_policy_document.combined[0].json
  
  depends_on = [aws_s3_bucket_lifecycle_configuration.this]
}

data "aws_iam_policy_document" "combined" {
  count = local.create_bucket && local.attach_policy ? 1 : 0

  source_policy_documents = compact([
    var.attach_elb_log_delivery_policy ? data.aws_iam_policy_document.elb_log_delivery[0].json : "",
    var.attach_lb_log_delivery_policy ? data.aws_iam_policy_document.lb_log_delivery[0].json : "",
    var.attach_require_latest_tls_policy ? data.aws_iam_policy_document.require_latest_tls[0].json : "",
    var.attach_deny_insecure_transport_policy ? data.aws_iam_policy_document.deny_insecure_transport[0].json : "",
    var.attach_inventory_destination_policy || var.attach_analytics_destination_policy ? data.aws_iam_policy_document.inventory_and_analytics_destination_policy[0].json : "",
    var.attach_policy ? var.policy : ""
  ])
  
  depends_on = [aws_s3_bucket_lifecycle_configuration.this]
}

# AWS Load Balancer access log delivery policy
locals {
  # List of AWS regions where permissions should be granted to the specified Elastic Load Balancing account ID ( https://docs.aws.amazon.com/elasticloadbalancing/latest/application/enable-access-logging.html#attach-bucket-policy )
  elb_service_accounts = {
    us-east-1      = "127311923021"
    us-east-2      = "033677994240"
    us-west-1      = "027434742980"
    us-west-2      = "797873946194"
    af-south-1     = "098369216593"
    ap-east-1      = "754344448648"
    ap-south-1     = "718504428378"
    ap-northeast-1 = "582318560864"
    ap-northeast-2 = "600734575887"
    ap-northeast-3 = "383597477331"
    ap-southeast-1 = "114774131450"
    ap-southeast-2 = "783225319266"
    ap-southeast-3 = "589379963580"
    ca-central-1   = "985666609251"
    eu-central-1   = "054676820928"
    eu-west-1      = "156460612806"
    eu-west-2      = "652711504416"
    eu-west-3      = "009996457667"
    eu-south-1     = "635631232127"
    eu-north-1     = "897822967062"
    me-south-1     = "076674570225"
    sa-east-1      = "507241528517"
    us-gov-west-1  = "048591011584"
    us-gov-east-1  = "190560391635"
  }
}

data "aws_iam_policy_document" "elb_log_delivery" {
  count = local.create_bucket && var.attach_elb_log_delivery_policy ? 1 : 0

  # Policy for AWS Regions created before August 2022 (e.g. US East (N. Virginia), Asia Pacific (Singapore), Asia Pacific (Sydney), Asia Pacific (Tokyo), Europe (Ireland))
  dynamic "statement" {
    for_each = { for k, v in local.elb_service_accounts : k => v if k == data.aws_region.current.name }

    content {
      sid = format("ELBRegion%s", title(statement.key))

      principals {
        type        = "AWS"
        identifiers = [format("arn:%s:iam::%s:root", data.aws_partition.current.partition, statement.value)]
      }

      effect = "Allow"

      actions = [
        "s3:PutObject",
      ]

      resources = [
        "${aws_s3_bucket.this[0].arn}/*",
      ]
    }
  }

  # Policy for AWS Regions created after August 2022 (e.g. Asia Pacific (Hyderabad), Asia Pacific (Melbourne), Europe (Spain), Europe (Zurich), Middle East (UAE))
  statement {
    sid = ""

    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }

    effect = "Allow"

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "${aws_s3_bucket.this[0].arn}/*",
    ]
  }
}

# ALB/NLB
data "aws_iam_policy_document" "lb_log_delivery" {
  count = local.create_bucket && var.attach_lb_log_delivery_policy ? 1 : 0

  statement {
    sid = "AWSLogDeliveryWrite"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    effect = "Allow"

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "${aws_s3_bucket.this[0].arn}/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid = "AWSLogDeliveryAclCheck"

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
    ]

    resources = [
      aws_s3_bucket.this[0].arn,
    ]

  }
}

data "aws_iam_policy_document" "deny_insecure_transport" {
  count = local.create_bucket && var.attach_deny_insecure_transport_policy ? 1 : 0

  statement {
    sid    = "denyInsecureTransport"
    effect = "Deny"

    actions = [
      "s3:*",
    ]

    resources = [
      aws_s3_bucket.this[0].arn,
      "${aws_s3_bucket.this[0].arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values = [
        "false"
      ]
    }
  }
}

data "aws_iam_policy_document" "require_latest_tls" {
  count = local.create_bucket && var.attach_require_latest_tls_policy ? 1 : 0

  statement {
    sid    = "denyOutdatedTLS"
    effect = "Deny"

    actions = [
      "s3:*",
    ]

    resources = [
      aws_s3_bucket.this[0].arn,
      "${aws_s3_bucket.this[0].arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "NumericLessThan"
      variable = "s3:TlsVersion"
      values = [
        "1.2"
      ]
    }
  }
  depends_on = [aws_s3_bucket_lifecycle_configuration.this]
}

resource "aws_s3_bucket_public_access_block" "this" {

  # Chain resources (s3_bucket -> s3_bucket_policy -> s3_bucket_public_access_block)
  # to prevent "A conflicting conditional operation is currently in progress against this resource."
  # Ref: https://github.com/hashicorp/terraform-provider-aws/issues/7628

  bucket =  aws_s3_bucket.this[0].id

  block_public_acls       = var.block_public_acls
  block_public_policy     = var.block_public_policy
  ignore_public_acls      = var.ignore_public_acls
  restrict_public_buckets = var.restrict_public_buckets
  
}

  
resource "aws_s3_bucket_ownership_controls" "this" {
  count = local.create_bucket && var.control_object_ownership ? 1 : 0

  bucket = local.attach_policy ? aws_s3_bucket_policy.this[0].id : aws_s3_bucket.this[0].id

  rule {
    object_ownership = var.object_ownership
  }

  # This `depends_on` is to prevent "A conflicting conditional operation is currently in progress against this resource."
  depends_on = [
    aws_s3_bucket_policy.this,
    aws_s3_bucket_public_access_block.this,
    aws_s3_bucket.this,
    aws_s3_bucket_lifecycle_configuration.this
  ]
}

resource "aws_s3_bucket_intelligent_tiering_configuration" "this" {
  for_each = { for k, v in local.intelligent_tiering : k => v if local.create_bucket }

  name   = each.key
  bucket = aws_s3_bucket.this[0].id
  status = try(tobool(each.value.status) ? "Enabled" : "Disabled", title(lower(each.value.status)), null)

  # Max 1 block - filter
  dynamic "filter" {
    for_each = length(try(flatten([each.value.filter]), [])) == 0 ? [] : [true]

    content {
      prefix = try(each.value.filter.prefix, null)
      tags   = try(each.value.filter.tags, null)
    }
  }

  dynamic "tiering" {
    for_each = each.value.tiering

    content {
      access_tier = tiering.key
      days        = tiering.value.days
    }
  }
    
    depends_on = [aws_s3_bucket_lifecycle_configuration.this]

}

resource "aws_s3_bucket_metric" "this" {
  for_each = { for k, v in local.metric_configuration : k => v if local.create_bucket }

  name   = each.value.name
  bucket = aws_s3_bucket.this[0].id

  dynamic "filter" {
    for_each = length(try(flatten([each.value.filter]), [])) == 0 ? [] : [true]
    content {
      prefix = try(each.value.filter.prefix, null)
      tags   = try(each.value.filter.tags, null)
    }
  }
}

resource "aws_s3_bucket_inventory" "this" {
  for_each = { for k, v in var.inventory_configuration : k => v if local.create_bucket }

  name                     = each.key
  bucket                   = try(each.value.bucket, aws_s3_bucket.this[0].id)
  included_object_versions = each.value.included_object_versions
  enabled                  = try(each.value.enabled, true)
  optional_fields          = try(each.value.optional_fields, null)

  destination {
    bucket {
      bucket_arn = try(each.value.destination.bucket_arn, aws_s3_bucket.this[0].arn)
      format     = try(each.value.destination.format, null)
      account_id = try(each.value.destination.account_id, null)
      prefix     = try(each.value.destination.prefix, null)

      dynamic "encryption" {
        for_each = length(try(flatten([each.value.destination.encryption]), [])) == 0 ? [] : [true]

        content {

          dynamic "sse_kms" {
            for_each = each.value.destination.encryption.encryption_type == "sse_kms" ? [true] : []

            content {
              key_id = try(each.value.destination.encryption.kms_key_id, null)
            }
          }

          dynamic "sse_s3" {
            for_each = each.value.destination.encryption.encryption_type == "sse_s3" ? [true] : []

            content {
            }
          }
        }
      }
    }
  }

  schedule {
    frequency = each.value.frequency
  }

  dynamic "filter" {
    for_each = length(try(flatten([each.value.filter]), [])) == 0 ? [] : [true]

    content {
      prefix = try(each.value.filter.prefix, null)
    }
  }
    depends_on = [aws_s3_bucket_lifecycle_configuration.this]
}

# Inventory and analytics destination bucket requires a bucket policy to allow source to PutObjects
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html#example-bucket-policies-use-case-9
data "aws_iam_policy_document" "inventory_and_analytics_destination_policy" {
  count = local.create_bucket && var.attach_inventory_destination_policy || var.attach_analytics_destination_policy ? 1 : 0

  statement {
    sid    = "destinationInventoryAndAnalyticsPolicy"
    effect = "Allow"

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "${aws_s3_bucket.this[0].arn}/*",
    ]

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values = compact(distinct([
        var.inventory_self_source_destination ? aws_s3_bucket.this[0].arn : var.inventory_source_bucket_arn,
        var.analytics_self_source_destination ? aws_s3_bucket.this[0].arn : var.analytics_source_bucket_arn
      ]))
    }

    condition {
      test = "StringEquals"
      values = compact(distinct([
        var.inventory_self_source_destination ? data.aws_caller_identity.current.id : var.inventory_source_account_id,
        var.analytics_self_source_destination ? data.aws_caller_identity.current.id : var.analytics_source_account_id
      ]))
      variable = "aws:SourceAccount"
    }

    condition {
      test     = "StringEquals"
      values   = ["bucket-owner-full-control"]
      variable = "s3:x-amz-acl"
    }
  }
}

resource "aws_s3_bucket_analytics_configuration" "this" {
  for_each = { for k, v in var.analytics_configuration : k => v if local.create_bucket }

  bucket = aws_s3_bucket.this[0].id
  name   = each.key

  dynamic "filter" {
    for_each = length(try(flatten([each.value.filter]), [])) == 0 ? [] : [true]

    content {
      prefix = try(each.value.filter.prefix, null)
      tags   = try(each.value.filter.tags, null)
    }
  }

  dynamic "storage_class_analysis" {
    for_each = length(try(flatten([each.value.storage_class_analysis]), [])) == 0 ? [] : [true]

    content {

      data_export {
        output_schema_version = try(each.value.storage_class_analysis.output_schema_version, null)

        destination {

          s3_bucket_destination {
            bucket_arn        = try(each.value.storage_class_analysis.destination_bucket_arn, aws_s3_bucket.this[0].arn)
            bucket_account_id = try(each.value.storage_class_analysis.destination_account_id, data.aws_caller_identity.current.id)
            format            = try(each.value.storage_class_analysis.export_format, "CSV")
            prefix            = try(each.value.storage_class_analysis.export_prefix, null)
          }
        }
      }
    }
  }
    depends_on = [aws_s3_bucket_lifecycle_configuration.this]
}
