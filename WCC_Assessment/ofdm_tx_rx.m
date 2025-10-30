% Simulate using MATLAB, OFDM. (orthogonal frequency-division multiplexing) 
% transmitter for {FFT length, CP length, number of occupied subcarriers, subcarrier spacing, pilot subcarrier spacing, channel BW}: = {128, 32, 72, 15e3, 9, 1.4e6} respectively 
% and modulation 16 QAM, code rate  is 2/3. Also write the meaning and usage of all the parameter

clc; clear; close all;
 % Parameters
 N_FFT = 128;
 N_CP = 32;
 N_data = 72;
 pilot_spacing = 9;
 mod_order = 16;
 bits_per_symbol = log2(mod_order);
 % Input bits
 tx_bits = [1 0 1 1  0 1 0 0  1 1 0 0  0 1 1 0];
 % Padding
 if mod(length(tx_bits), bits_per_symbol) ~= 0
    pad = bits_per_symbol - mod(length(tx_bits), bits_per_symbol);
    tx_bits = [tx_bits, zeros(1,pad)];
 else
    pad = 0;
 end
 
 % QAM mapping
 tx_symbols_int = bi2de(reshape(tx_bits, bits_per_symbol, []).', 'left-msb');
 tx_qam = qammod(tx_symbols_int, mod_order, 'InputType', 'integer', 
'UnitAveragePower', true);

 % Subcarrier allocation
 start_idx = floor((N_FFT - N_data)/2) + 1;
 data_block = start_idx : (start_idx + N_data - 1);
 pilot_rel_pos = 1:pilot_spacing:N_data;
 pilot_indices = data_block(pilot_rel_pos);
 data_positions = setdiff(data_block, pilot_indices, 'stable');
 num_map = min(length(tx_qam), length(data_positions));
 ofdm_grid = zeros(N_FFT,1);
 ofdm_grid(data_positions(1:num_map)) = tx_qam(1:num_map);
 ofdm_grid(pilot_indices) = 1 + 1j;  % pilot value
 
 % ---------------- TX side ---------------
tx_time = ifft(ifftshift(ofdm_grid));
 tx_ofdm = [tx_time(end-N_CP+1:end); tx_time];
 % Plot TX OFDM symbol (time domain)
 figure('Name','TX Time Domain OFDM Symbol');
 plot(real(tx_time), '-o'); hold on; plot(imag(tx_time), '-x');
 title('TX: OFDM Time-Domain Symbol (without CP)');
 xlabel('Sample index'); ylabel('Amplitude');
 legend('Real part','Imag part'); grid on;
 
% Plot TX OFDM with CP
 figure('Name','TX OFDM with Cyclic Prefix');
 plot(real(tx_ofdm), '-o'); hold on; plot(imag(tx_ofdm), '-x');
 title('TX: OFDM Symbol with Cyclic Prefix');
 xlabel('Sample index'); ylabel('Amplitude');
 legend('Real part','Imag part'); grid on;
 % Plot TX Frequency-domain grid
 figure('Name','TX Frequency Grid');
 stem(abs(ofdm_grid),'filled');
 title('TX: Magnitude of Frequency Bins (pilots + data)');
 xlabel('FFT bin index'); ylabel('|Amplitude|'); grid on;
 
 % ---------------- Channel ---------------
snr_dB = 30;
 rx_ofdm = awgn(tx_ofdm, snr_dB, 'measured');
 
 % ---------------- RX side ---------------
rx_noCP = rx_ofdm(N_CP+1:N_CP+N_FFT);
 rx_freq = fftshift(fft(rx_noCP));
 % Plot RX OFDM time signal (with noise)
 figure('Name','RX OFDM Time-Domain Symbol');
 plot(real(rx_noCP), '-o'); hold on; plot(imag(rx_noCP), '-x');
 title(sprintf('RX: No-CP Time Signal (SNR = %.1f dB)', snr_dB));
 xlabel('Sample index'); ylabel('Amplitude');
 legend('Real part','Imag part'); grid on;
 
 % Plot RX Frequency grid
 figure('Name','RX Frequency Grid');
 stem(abs(rx_freq),'filled');
 title('RX: Magnitude of Frequency Bins after FFT');
 xlabel('FFT bin index'); ylabel('|Amplitude|'); grid on;
 
 % Extract data
 rx_data_at_data_positions = rx_freq(data_positions);
 rx_data_used = rx_data_at_data_positions(1:num_map);
 % Demodulate
 rx_symbols_int = qamdemod(rx_data_used, mod_order, 'OutputType', 'integer', 
'UnitAveragePower', true);
 rx_bits_matrix = de2bi(rx_symbols_int, bits_per_symbol, 'left-msb');
 rx_bits = reshape(rx_bits_matrix.', 1, []);
 if pad > 0
    rx_bits = rx_bits(1:end-pad);
 end
 
 % ---------------- Results ---------------
fprintf('Transmitted bits:  '); disp(tx_bits(1:end-pad));
 fprintf('Recovered bits:    '); disp(rx_bits);
 fprintf('Bit errors: %d (SNR = %d dB)\n', sum(rx_bits ~= tx_bits(1:end-pad)), 
snr_dB);
 % ---------------- Constellations ---------------
figure('Name','Constellation TX vs RX');
 subplot(2,1,1);
 plot(real(tx_qam), imag(tx_qam), 'o');
 title('TX QAM Symbols');
 axis equal; grid on;
 subplot(2,1,2);
 plot(real(rx_data_used), imag(rx_data_used), 'x');
 title('RX Received Symbols (after FFT & demod)');
 axis equal; grid on;
