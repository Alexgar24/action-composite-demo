# Example of insecure Terraform configuration

# Bad: S3 bucket without encryption
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-bucket"
  acl    = "public-read"  # Bad: Public access
}

# Bad: Security group with unrestricted access
resource "aws_security_group" "insecure_sg" {
  name        = "allow_all"
  description = "Allow all traffic"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # Bad: Open to the world
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Bad: RDS without encryption
resource "aws_db_instance" "insecure_db" {
  identifier     = "mydb"
  engine         = "mysql"
  engine_version = "5.7"
  instance_class = "db.t3.micro"
  
  username = "admin"
  password = "supersecretpassword123"  # Bad: Hardcoded password
  
  storage_encrypted = false  # Bad: No encryption
  publicly_accessible = true  # Bad: Public access
}

# Bad: EC2 instance with public IP and no key
resource "aws_instance" "insecure_instance" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
  
  associate_public_ip_address = true  # Potential issue
  
  metadata_options {
    http_tokens = "optional"  # Bad: Should be "required"
  }
}