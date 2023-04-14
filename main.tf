
locals {
  create_bucket = var.create_bucket && var.putin_khuylo

  #attach_policy = var.attach_require_latest_tls_policy || var.attach_elb_log_delivery_policy || var.attach_lb_log_delivery_policy || var.attach_deny_insecure_transport_policy || var.attach_inventory_destination_policy || var.attach_policy

}

resource "aws_s3_bucket" "buck" {

  bucket        = var.bucket
  bucket_prefix = var.bucket_prefix

  force_destroy       = var.force_destroy
  object_lock_enabled = var.object_lock_enabled
  tags                = var.tags
}


resource "aws_s3_bucket_public_access_block" "this" {

  bucket =  aws_s3_bucket.buck.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  
  depends_on = [aws_s3_bucket.buck]
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  bucket = aws_s3_bucket.buck.id

  rule {
    id     = "Incomplete multi-part uploads"
    status = "Enabled"

    abort_incomplete_multipart_upload {
      days_after_initiation = 8
    }
  }
  depends_on = [aws_s3_bucket.buck]
}
