# Example of secure Terraform configuration

# Good: S3 bucket with encryption and versioning
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure_bucket_pab" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "secure_bucket_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# Good: Security group with restricted access
resource "aws_security_group" "secure_sg" {
  name        = "secure_web"
  description = "Security group for web servers"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]  # Good: Restricted to VPC
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Good: RDS with encryption
resource "aws_db_instance" "secure_db" {
  identifier     = "mydb-secure"
  engine         = "postgres"
  engine_version = "14"
  instance_class = "db.t3.micro"
  
  username = "dbadmin"
  password = var.db_password  # Good: Using variable
  
  storage_encrypted   = true   # Good: Encrypted
  publicly_accessible = false  # Good: Not public
  
  backup_retention_period = 7  # Good: Backups enabled
}