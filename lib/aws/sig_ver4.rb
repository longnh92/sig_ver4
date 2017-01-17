require "openssl"
require "time"

module Aws
  class SigVer4
    ISO8601_DATE_FORMAT_STR = '%Y%m%dT%H%M%SZ'
    DATE_STAMP_FORMAT_STR = '%Y%m%d'
    DEFAULT_SIGNED_HEADERS = [:'content-type', :'host', :'x-amz-content-sha256', :'x-amz-date']
    HASH_ALGORITHM = 'AWS4-HMAC-SHA256'

    def initialize(params)
      extract_aws_data(params[:aws])
      extract_request_data(params[:request])
    end

    def signing_headers
      generate_date_info
      step_1_create_canonical_request
      step_2_create_string_to_sign
      step_3_calculate_the_signature
      step_4_generate_signing_headers
    end

    private

    def extract_aws_data(aws_data)
      fail 'Need to define AWS data' unless aws_data
      @aws_access_key = aws_data[:access_key]
      @aws_secret_key = aws_data[:secret_key]
      @aws_region     = aws_data[:region]
      @aws_service    = aws_data[:service]
    end

    def extract_request_data(request_data)
      fail 'Need to define request data' unless request_data
      @host = request_data[:host]
      @req_method = request_data[:method]
      @req_params = request_data[:params] || ''
      @req_body = request_data[:body] || ''
      @req_headers = request_data[:headers] || {}
      @canonical_uri = request_data[:canonical_uri] || '/'
      @content_type = request_data[:content_type]
    end

    def generate_date_info
      current_time = Time.now.utc
      @amz_date = current_time.strftime(ISO8601_DATE_FORMAT_STR)
      @datestamp = current_time.strftime(DATE_STAMP_FORMAT_STR)
    end

    def hmac(key, data)
      OpenSSL::HMAC.digest('sha256', key, data)
    end

    def hex_hmac(key, value)
      OpenSSL::HMAC.hexdigest('sha256', key, value)
    end

    def hexdigest(value)
      OpenSSL::Digest.new("sha256").hexdigest(value)
    end

    def step_1_create_canonical_request
      @canonical_request = [
        @req_method, 
        @canonical_uri, 
        @req_params, 
        canonical_headers, 
        signed_headers, 
        payload_hash
      ].join("\n")
    end

    def canonical_headers
      @req_headers.merge({
        :'content-type' => @content_type,
        :'host' => @host,
        :'x-amz-content-sha256' => payload_hash,
        :'x-amz-date' => @amz_date
      }).sort.map {|k, v| "#{k.downcase}:#{v.strip}"}.
      join("\n") << "\n"
    end

    def signed_headers
      @signed_headers ||= (@req_headers.keys.map(&:downcase) | DEFAULT_SIGNED_HEADERS).sort.join(';')
    end

    def payload_hash
      @payload_hash ||= hexdigest(@req_body)
    end

    def step_2_create_string_to_sign
      @string_to_sign = [
        HASH_ALGORITHM, 
        @amz_date, 
        credential_scope,
        hexdigest(@canonical_request)
      ].join("\n")
    end

    def credential_scope
      [
        @datestamp, 
        @aws_region, 
        @aws_service, 
        'aws4_request'
      ].join("/")
    end

    def step_3_calculate_the_signature
      @signing_key = getSignatureKey
    end

    def getSignatureKey
      date_key    = hmac("AWS4#{@aws_secret_key}", @datestamp)
      region_key  = hmac(date_key, @aws_region)
      service_key = hmac(region_key, @aws_service)
      hmac(service_key, "aws4_request")
    end

    def step_4_generate_signing_headers
      @req_headers.merge({
        'Content-Type' => @content_type,
        'X-Amz-Content-Sha256' => payload_hash,
        'X-Amz-Date' => @amz_date,
        'Authorization' => authorization_key
      })
    end

    def authorization_key
      "#{HASH_ALGORITHM} Credential=#{@aws_access_key}/#{credential_scope}, SignedHeaders=#{signed_headers}, Signature=#{signature}"
    end

    def signature
      hex_hmac(@signing_key, @string_to_sign)
    end

  end
end
