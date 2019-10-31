function hashed = hasher( toHash, varargin )
%HASHER Calculates hash of character or numeric arrays
% hasher( x )
% hasher( x, 'Algorithm', 'SHA256')
% Default algorithm is MD5.
%
% Ex: hash = hasher('try this') % MD5 hash
%
% Ex: hash = hasher(imread('001.bmp'), 'SHA1')
%
%     SIZE OF THE DIFFERENT HASHES:
%           SHA1:  20 bytes = 20 hex codes =  40 char hash string
%         SHA256:  32 bytes = 32 hex codes =  64 char hash string
%         SHA384:  48 bytes = 48 hex codes =  96 char hash string
%         SHA512:  64 bytes = 64 hex codes = 128 char hash string
%            MD5:  16 bytes = 16 hex codes =  32 char hash string
NET.addAssembly('System.Security');

    [varargin{:}] = convertStringsToChars(varargin{:});
    try toHash = cell2mat(toHash); end %#ok
    persistent p
    
    if isempty(p)
        p = inputParser;
        addRequired(p, 'toHash', @(x) validateattributes(x, {'char', 'numeric'}, {'nonempty'}, 1))
        addParameter(p, 'Algorithm', 'MD5', @(x) ischar(x) && any(contains({'MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512'}, x)))
    end
    p.parse(toHash, varargin{:})
    alg = p.Results.Algorithm;
    
    % Hashing the input:
    hashMasher = System.Security.Cryptography.HashAlgorithm.Create(alg);
    hash_byte = hashMasher.ComputeHash( uint8(toHash(:)) );  % System.Byte class
    hash_uint8 = uint8( hash_byte );               % Array of uint8
    hashed = dec2hex(hash_uint8);                % Array of 2-char hex codes
    
    % Converting hash to a char vector:
    hashed = hashed(:)';
end % End hasher.m