require "openssl"
require "time"

module Aws
  class SigVer4
    ISO8601_DATE_FORMAT_STR = '%Y%m%dT%H%M%SZ'
    DATE_STAMP_FORMAT_STR = '%Y%m%d'
    DEFAULT_SIGNED_HEADERS = ['content-type', 'host', 'x-amz-content-sha256', 'x-amz-date']
    HASH_ALGORITHM = 'AWS4-HMAC-SHA256'

    def initialize(params)
      extract_aws_data(params[:aws])
      extract_request_data(params[:request])
    end

    def request_headers
      generate_date_info
      step_1_create_canonical_request
      step_2_create_string_to_sign
      step_3_calculate_the_signature
      step_4_generate_request_headers
    end

    private

    def extract_aws_data(aws_data)
      fail 'Need to define AWS data' unless aws_data
      @aws_access_key = aws_data[:aws_access_key]
      @aws_secret_key = aws_data[:aws_secret_key]
      @region         = aws_data[:region]
      @aws_service    = aws_data[:aws_service]
    end

    def extract_request_data(request_data)
      fail 'Need to define request data' unless request_data
      @host = request_data[:host]
      @req_method = request_data[:req_method]
      @req_params = request_data[:params] || ''
      @req_body = request_data[:body] || ''
      @req_headers = request_data[:headers]
      @canonical_uri = request_data[:canonical_uri]
      @content_type = request_data[:content_type]
    end

    def generate_date_info
      current_time = Time.now.utc
      @amz_date = current_time.strftime(ISO8601_DATE_FORMAT_STR)
      @datestamp = current_time.strftime(DATE_STAMP_FORMAT_STR)
    end

    def hmac_encode(key, data)
      OpenSSL::HMAC.digest('sha256', key, data)
    end

    def step_1_create_canonical_request
      @canonical_request = [
        @params[:request_method], 
        @params[:canonical_uri], 
        @params[:request_params] || '', 
        canonical_headers,
        SIGNED_HEADERS, 
        payload_hash
      ].join("\n")
    end

    def canonical_headers
      [
        "content-type:#{@params[:content_type]}",
        "host:#{@params[:host]}", 
        "x-amz-content-sha256:#{payload_hash}",
        "x-amz-date:#{@amz_date}"
      ].join("\n") << "\n"
    end

    def payload_hash
      @payload_hash ||= OpenSSL::Digest.new("sha256").hexdigest(@params[:request_body] || '')
    end

    def step_2_create_string_to_sign
      @string_to_sign = [
        HASH_ALGORITHM, @amz_date, credential_scope,
        OpenSSL::Digest.new("sha256").hexdigest(@canonical_request)
      ].join("\n")
    end

    def credential_scope
      [
        @datestamp, 
        @params[:region], 
        @params[:aws_service], 
        'aws4_request'
      ].join("/")
    end

    def step_3_calculate_the_signature
      @signing_key = getSignatureKey
    end

    def getSignatureKey
      date_key    = hmac_encode("AWS4#{@params[:aws_secret_key]}", @datestamp)
      region_key  = hmac_encode(date_key, @params[:region])
      service_key = hmac_encode(region_key, @params[:aws_service])
      hmac_encode(service_key, "aws4_request")
    end

    def step_4_generate_request_headers
      {
        'Content-Type' => @params[:content_type],
        'X-Amz-Content-Sha256' => payload_hash,
        'X-Amz-Date' => @amz_date,
        'Authorization' => authorization_key
      }
    end

    def authorization_key
      "#{HASH_ALGORITHM} Credential=#{@params[:aws_access_id]}/#{credential_scope}, SignedHeaders=#{SIGNED_HEADERS}, Signature=#{signature}"
    end

    def signature
      OpenSSL::HMAC.hexdigest('sha256', @signing_key, @string_to_sign)
    end

  end
end
