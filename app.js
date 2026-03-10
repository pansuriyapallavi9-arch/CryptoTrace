var evidenceRecords = [];
var caseIdCounter = 1;

var dropZone = document.getElementById('dropZone');
var fileInput = document.getElementById('fileInput');
var textInput = document.getElementById('textInput');
var resultsSection = document.getElementById('resultsSection');
var resultsContainer = document.getElementById('resultsContainer');
var caseList = document.getElementById('caseList');
var totalCases = document.getElementById('totalCases');
var encryptedCount = document.getElementById('encryptedCount');
var suspiciousCount = document.getElementById('suspiciousCount');
var clearCount = document.getElementById('clearCount');

dropZone.addEventListener('click', function() {
    fileInput.click();
});

dropZone.addEventListener('dragover', function(e) {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', function() {
    dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', function(e) {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    var files = e.dataTransfer.files;
    handleFiles(files);
});

fileInput.addEventListener('change', function(e) {
    handleFiles(e.target.files);
});

function handleFiles(files) {
    for (var i = 0; i < files.length; i++) {
        analyzeFile(files[i]);
    }
}

function analyzeFile(file) {
    var reader = new FileReader();
    
    reader.onload = function(e) {
        var content = e.target.result;
        
        var metadata = {
            name: file.name,
            size: formatBytes(file.size),
            sizeRaw: file.size,
            type: file.type || 'Unknown',
            lastModified: new Date(file.lastModified).toLocaleString(),
            timestamp: Date.now()
        };

        generateHash(content).then(function(hash) {
            metadata.hash = hash;
            var analysis = analyzeContent(content, file.name);
            
            var record = {
                id: caseIdCounter++,
                metadata: metadata,
                analysis: analysis,
                type: 'file',
                timestamp: Date.now()
            };

            evidenceRecords.push(record);
            displayResults(record);
            updateCaseList();
            updateStats();
        });
    };

    reader.readAsArrayBuffer(file);
}

function analyzeText() {
    var text = textInput.value.trim();
    
    if (!text) {
        alert('Please enter some text to analyze');
        return;
    }

    var metadata = {
        name: 'Text Input Analysis',
        size: formatBytes(new Blob([text]).size),
        sizeRaw: new Blob([text]).size,
        type: 'Plain Text',
        timestamp: Date.now(),
        created: new Date().toLocaleString()
    };

    generateHash(text).then(function(hash) {
        metadata.hash = hash;
        
        var analysis = analyzeContent(text, 'text_input');
        
        var record = {
            id: caseIdCounter++,
            metadata: metadata,
            analysis: analysis,
            type: 'text',
            content: text,
            timestamp: Date.now()
        };

        evidenceRecords.push(record);
        displayResults(record);
        updateCaseList();
        updateStats();
        
        textInput.value = '';
    });
}

function analyzeContent(content, filename) {
    var analysis = {
        isEncrypted: false,
        suspiciousPatterns: [],
        detectedCiphers: [],
        recommendations: [],
        securityLevel: 'clear',
        confidence: 0
    };

    var textContent = '';
    if (typeof content === 'string') {
        textContent = content;
    } else {
        var bytes = new Uint8Array(content);
        var hexArray = [];
        for (var i = 0; i < bytes.length; i++) {
            hexArray.push(bytes[i].toString(16).padStart(2, '0'));
        }
        textContent = hexArray.join('');
    }

    var cleanText = textContent.replace(/\s/g, '');

    var base64Pattern = /^[A-Za-z0-9+/]+=*$/;
    if (base64Pattern.test(cleanText) && cleanText.length > 20) {
        analysis.detectedCiphers.push('Base64 Encoding Detected');
        analysis.suspiciousPatterns.push('Content matches Base64 character set');
        analysis.isEncrypted = true;
        analysis.confidence += 30;
        analysis.recommendations.push('Decode using Base64 decoder');
        
        if (typeof content === 'string') {
            try {
                var decoded = atob(cleanText);
                analysis.recommendations.push('Decoded preview: "' + decoded.substring(0, 50) + '"');
            } catch (e) {
                analysis.recommendations.push('Base64 decoding failed');
            }
        }
    }

    var hexPattern = /^[0-9A-Fa-f]+$/;
    if (hexPattern.test(cleanText) && cleanText.length > 32 && cleanText.length % 2 === 0) {
        analysis.detectedCiphers.push('Hexadecimal Encoding Detected');
        analysis.suspiciousPatterns.push('Content contains only hex digits');
        analysis.confidence += 25;
        analysis.recommendations.push('Convert from hexadecimal to ASCII');
    }

    var hasOnlyLetters = /^[A-Za-z\s]+$/.test(textContent);
    var hasNoNumbers = !/[0-9]/.test(textContent);
    
    if (hasOnlyLetters && hasNoNumbers && textContent.length > 10 && textContent.length < 1000) {
        analysis.detectedCiphers.push('Possible Caesar/ROT13 Cipher');
        analysis.suspiciousPatterns.push('Text contains only alphabetic characters');
        analysis.confidence += 20;
        analysis.recommendations.push('Try ROT13 decryption');
        
        var rot13decoded = rot13(textContent);
        analysis.recommendations.push('ROT13 decoded: "' + rot13decoded.substring(0, 50) + '"');
    }

    var entropy = calculateEntropy(textContent);
    analysis.entropy = entropy.toFixed(2);
    
    if (entropy > 7.5) {
        analysis.suspiciousPatterns.push('Very high entropy - likely strong encryption');
        analysis.isEncrypted = true;
        analysis.confidence += 40;
        analysis.recommendations.push('High entropy indicates AES or RSA encryption');
    } else if (entropy > 6.0) {
        analysis.suspiciousPatterns.push('High entropy - possibly encrypted');
        analysis.isEncrypted = true;
        analysis.confidence += 30;
        analysis.recommendations.push('Could be encrypted or compressed data');
    } else if (entropy > 4.5) {
        analysis.suspiciousPatterns.push('Moderate entropy - may contain encoded data');
        analysis.confidence += 15;
        analysis.recommendations.push('Possible encoding or obfuscation');
    } else {
        analysis.suspiciousPatterns.push('Low entropy - appears normal');
    }

    var encryptedExts = ['.enc', '.encrypted', '.aes', '.pgp', '.gpg'];
    var suspiciousExts = ['.exe', '.bat', '.cmd', '.ps1', '.vbs', '.js'];
    
    var lowerName = filename.toLowerCase();
    
    for (var i = 0; i < encryptedExts.length; i++) {
        if (lowerName.endsWith(encryptedExts[i])) {
            analysis.detectedCiphers.push('Encrypted file extension');
            analysis.isEncrypted = true;
            analysis.confidence += 35;
        }
    }
    
    for (var i = 0; i < suspiciousExts.length; i++) {
        if (lowerName.endsWith(suspiciousExts[i])) {
            analysis.suspiciousPatterns.push('Suspicious executable extension');
            analysis.confidence += 20;
        }
    }

    if (typeof content !== 'string') {
        var bytes = new Uint8Array(content);
        var sig = detectFileSignature(bytes);
        if (sig) {
            analysis.detectedCiphers.push('File Type: ' + sig.type);
            analysis.recommendations.push(sig.description);
        }
    }

    if (analysis.confidence >= 60 || analysis.isEncrypted) {
        analysis.securityLevel = 'encrypted';
    } else if (analysis.confidence >= 30) {
        analysis.securityLevel = 'suspicious';
    } else {
        analysis.securityLevel = 'clear';
    }

    if (analysis.suspiciousPatterns.length === 0) {
        analysis.suspiciousPatterns.push('No suspicious patterns detected');
    }

    if (analysis.recommendations.length === 0) {
        analysis.recommendations.push('File appears clean');
    }

    return analysis;
}

function calculateEntropy(str) {
    var len = str.length;
    var freq = {};
    
    for (var i = 0; i < len; i++) {
        var c = str[i];
        freq[c] = (freq[c] || 0) + 1;
    }

    var entropy = 0;
    for (var c in freq) {
        var p = freq[c] / len;
        entropy -= p * Math.log2(p);
    }

    return entropy;
}

function generateHash(data) {
    var encoder = new TextEncoder();
    var buffer;
    
    if (typeof data === 'string') {
        buffer = encoder.encode(data);
    } else {
        buffer = data;
    }

    return crypto.subtle.digest('SHA-256', buffer).then(function(hashBuffer) {
        var hashArray = Array.from(new Uint8Array(hashBuffer));
        var hashHex = '';
        for (var i = 0; i < hashArray.length; i++) {
            hashHex += hashArray[i].toString(16).padStart(2, '0');
        }
        return hashHex;
    });
}

function rot13(str) {
    return str.replace(/[A-Za-z]/g, function(c) {
        var start = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(start + (c.charCodeAt(0) - start + 13) % 26);
    });
}

function detectFileSignature(bytes) {
    var sigs = {
        'FFD8FF': { type: 'JPEG', description: 'JPEG image file' },
        '89504E47': { type: 'PNG', description: 'PNG image file' },
        '474946': { type: 'GIF', description: 'GIF image file' },
        '504B0304': { type: 'ZIP', description: 'ZIP archive' },
        '25504446': { type: 'PDF', description: 'PDF document' },
        '4D5A': { type: 'EXE', description: 'Windows executable - CAUTION' }
    };

    var hexSig = '';
    for (var i = 0; i < Math.min(16, bytes.length); i++) {
        hexSig += bytes[i].toString(16).toUpperCase().padStart(2, '0');
    }

    for (var sig in sigs) {
        if (hexSig.startsWith(sig)) {
            return sigs[sig];
        }
    }

    return null;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    var k = 1024;
    var sizes = ['Bytes', 'KB', 'MB', 'GB'];
    var i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function displayResults(record) {
    resultsSection.style.display = 'block';
    
    var badgeClass = record.analysis.securityLevel;
    var badgeText = badgeClass.charAt(0).toUpperCase() + badgeClass.slice(1);

    var html = '<div class="result-card">';
    html += '<div class="result-header">';
    html += '<div class="result-title">📄 ' + record.metadata.name + '</div>';
    html += '<span class="badge ' + badgeClass + '">' + badgeText + '</span>';
    html += '</div>';
    
    html += '<div class="metadata-grid">';
    html += '<div class="metadata-item"><div class="metadata-label">📊 File Size</div><div class="metadata-value">' + record.metadata.size + '</div></div>';
    html += '<div class="metadata-item"><div class="metadata-label">📝 Type</div><div class="metadata-value">' + record.metadata.type + '</div></div>';
    html += '<div class="metadata-item"><div class="metadata-label">🔐 Hash</div><div class="metadata-value" style="font-size:0.75em;">' + record.metadata.hash.substring(0, 20) + '...</div></div>';
    html += '<div class="metadata-item"><div class="metadata-label">📅 Time</div><div class="metadata-value">' + (record.metadata.lastModified || record.metadata.created) + '</div></div>';
    
    if (record.analysis.entropy) {
        html += '<div class="metadata-item"><div class="metadata-label">🎲 Entropy</div><div class="metadata-value">' + record.analysis.entropy + ' / 8.0</div></div>';
    }
    
    html += '<div class="metadata-item"><div class="metadata-label">✅ Confidence</div><div class="metadata-value">' + record.analysis.confidence + '%</div></div>';
    html += '</div>';
    
    html += '<div class="analysis-section"><h3>🔍 Detection Results</h3>';
    
    if (record.analysis.detectedCiphers.length > 0) {
        html += '<div style="margin-bottom:15px;"><strong style="color:#667eea;">🔒 Detected:</strong><ul class="pattern-list">';
        for (var i = 0; i < record.analysis.detectedCiphers.length; i++) {
            html += '<li>' + record.analysis.detectedCiphers[i] + '</li>';
        }
        html += '</ul></div>';
    }
    
    html += '<div style="margin-bottom:15px;"><strong style="color:#667eea;">⚠️ Patterns:</strong><ul class="pattern-list">';
    for (var i = 0; i < record.analysis.suspiciousPatterns.length; i++) {
        html += '<li>' + record.analysis.suspiciousPatterns[i] + '</li>';
    }
    html += '</ul></div>';
    
    if (record.analysis.recommendations.length > 0) {
        html += '<div class="recommendation"><strong>💡 Recommendations:</strong><ul class="pattern-list">';
        for (var i = 0; i < record.analysis.recommendations.length; i++) {
            html += '<li>' + record.analysis.recommendations[i] + '</li>';
        }
        html += '</ul></div>';
    }
    
    html += '</div></div>';

    resultsContainer.innerHTML = html + resultsContainer.innerHTML;
}

function updateCaseList() {
    if (evidenceRecords.length === 0) {
        caseList.innerHTML = '<div class="no-results"><div class="empty-icon">📂</div><p>No evidence analyzed yet</p></div>';
        return;
    }

    var html = '';
    for (var i = evidenceRecords.length - 1; i >= 0; i--) {
        var rec = evidenceRecords[i];
        html += '<div class="case-item" onclick="viewCase(' + rec.id + ')">';
        html += '<div class="case-name">🔍 ' + rec.metadata.name;
        html += ' <span class="badge ' + rec.analysis.securityLevel + '" style="margin-left:10px;font-size:0.75em;padding:4px 10px;">' + rec.analysis.securityLevel + '</span>';
        html += '</div>';
        html += '<div class="case-date">📅 ' + (rec.metadata.lastModified || rec.metadata.created) + '</div>';
        html += '<div class="case-date">🔐 ' + rec.analysis.detectedCiphers.length + ' cipher(s) | Entropy: ' + (rec.analysis.entropy || 'N/A') + '</div>';
        html += '</div>';
    }

    caseList.innerHTML = html;
}

function updateStats() {
    totalCases.textContent = evidenceRecords.length;
    
    var enc = 0;
    var sus = 0;
    var clr = 0;

    for (var i = 0; i < evidenceRecords.length; i++) {
        if (evidenceRecords[i].analysis.securityLevel === 'encrypted') {
            enc++;
        } else if (evidenceRecords[i].analysis.securityLevel === 'suspicious') {
            sus++;
        } else {
            clr++;
        }
    }

    encryptedCount.textContent = enc;
    suspiciousCount.textContent = sus;
    clearCount.textContent = clr;
}

function viewCase(id) {
    for (var i = 0; i < evidenceRecords.length; i++) {
        if (evidenceRecords[i].id === id) {
            displayResults(evidenceRecords[i]);
            resultsSection.scrollIntoView({ behavior: 'smooth' });
            break;
        }
    }
}

function clearAllCases() {
    if (confirm('Are you sure you want to clear all cases?')) {
        evidenceRecords = [];
        caseIdCounter = 1;
        updateCaseList();
        updateStats();
        resultsContainer.innerHTML = '';
        resultsSection.style.display = 'none';
        alert('All cases cleared');
    }
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('CryptoTrace initialized');
    updateStats();
});