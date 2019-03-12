using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using uFR;



namespace mifare_plus_c_sharp
{

    using DL_STATUS = System.UInt32;

    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }



        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
             .Where(x => x % 2 == 0)
             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
             .ToArray();
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            DL_STATUS status = (UInt32)uFCoder.ReaderOpen();

            if (status == 0)
            {
                toolStripStatusLabel1.Text = "Communication port opened";
                tmrReaderOpen.Stop();
                txtStatus.Text = uFCoder.GetDescription();

                tmrReaderOpen.Stop();
                tmrCardReading.Start();
            }
            else
            {
                toolStripStatusLabel1.Text = "Port not opened. Status is : " + uFCoder.status2str((uFR.DL_STATUS)status) + " Searching for reader ...";
            }
        }

        private void timer2_Tick(object sender, EventArgs e)
        {
            DL_STATUS status = 0;

            byte cardtype_val = 0, sak = 0, uid_size = 0;
            byte[] uid = new byte[10];

            status = (UInt32)uFCoder.GetDlogicCardType(out cardtype_val);

            if (status > 0)
            {
                //toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                txtCardType.Text = uFCoder.status2str((uFR.DL_STATUS)status);
                txtCardUID.Text = BitConverter.ToString(uid).Replace("-", ":");
                return;
            }

            txtCardType.Text = Enum.GetName(typeof(DLOGIC_CARD_TYPE), cardtype_val);

            status = (UInt32)uFCoder.GetCardIdEx(out sak, uid, out uid_size);

            txtCardUID.Text = BitConverter.ToString(uid).Replace("-", ":");

            //toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }




        private void btnPersonalizeCard_Click(object sender, EventArgs e)
        {
            DL_STATUS status;

            byte[] master_key = new byte[16];
            byte[] config_key = new byte[16];
            byte[] l2_sw_key = new byte[16];
            byte[] l3_sw_key = new byte[16];
            byte[] l1_auth_key = new byte[16];
            byte[] sel_vc_key = new byte[16];
            byte[] prox_chk_key = new byte[16];
            byte[] vc_poll_enc_key = new byte[16];
            byte[] vc_poll_mac_key = new byte[16];
            byte dl_card_type = 0;

            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "No card in RF field found for Personalization";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            //check if card type S in SL0
            if (!((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL0 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_X_4K_SL0))
            {
                txtStatus.Text = "Card is not in security level 0 mode.";
                return;
            }

            /* if (dl_card_type == DL_MIFARE_PLUS_S_2K_SL0 || dl_card_type == DL_MIFARE_PLUS_S_4K_SL0)
            {
            } */

            if (txtPersonalizeCardMasterKey.TextLength != 32)
            {
                txtStatus.Text = "Master key must be 16 bytes long!";
                return;
            }

            if (txtPersonalizeConfigurationKey.TextLength != 32)
            {
                txtStatus.Text = "Card configuration key must be 16 bytes long!";
                return;
            }

            if (txtPersonalizeLevel2Key.TextLength != 32)
            {
                txtStatus.Text = "Level 2 switch key must be 16 bytes long!";
                return;
            }

            if (txtPersonalizeLevel3Key.TextLength != 32)
            {
                txtStatus.Text = "Level 3 switch key must be 16 bytes long!";
                return;
            }

            if (txtPersonalizeLevel1Key.TextLength != 32)
            {
                txtStatus.Text = "SL1 card authentication key must be 16 bytes long!";
                return;
            }

            if ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_X_2K_SL0 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_X_4K_SL0)
            {
                if (txtPersonalizeSelectVCKey.TextLength != 32)
                {
                    txtStatus.Text = "Select VC key must be 16 bytes long!";
                    return;
                }

                if (txtPersonalizeProximityCheckKey.TextLength != 32)
                {
                    txtStatus.Text = "Proximity check key must be 16 bytes long!";
                    return;
                }
            }

            if (txtPersonalizeVCENCKey.TextLength != 32)
            {
                txtStatus.Text = "VC polling ENC key key must be 16 bytes long!";
                return;
            }

            if (txtPersonalizeVCMACKey.TextLength != 32)
            {
                txtStatus.Text = "VC polling MAC key key must be 16 bytes long!";
                return;
            }


            // StringToByteArray(AESkeyTB.Text);

            master_key = StringToByteArray(txtPersonalizeCardMasterKey.Text);

            config_key = StringToByteArray(txtPersonalizeConfigurationKey.Text);

            l1_auth_key = StringToByteArray(txtPersonalizeLevel1Key.Text);

            l2_sw_key = StringToByteArray(txtPersonalizeLevel2Key.Text);

            l3_sw_key = StringToByteArray(txtPersonalizeLevel3Key.Text);

            sel_vc_key = StringToByteArray(txtPersonalizeSelectVCKey.Text);

            prox_chk_key = StringToByteArray(txtPersonalizeProximityCheckKey.Text);

            vc_poll_enc_key = StringToByteArray(txtPersonalizeVCENCKey.Text);

            vc_poll_mac_key = StringToByteArray(txtPersonalizeVCMACKey.Text);


            status = (UInt32)uFCoder.MFP_PersonalizationMinimal(master_key, config_key, l2_sw_key, l3_sw_key, l1_auth_key,
             sel_vc_key, prox_chk_key, vc_poll_enc_key, vc_poll_mac_key);

            if (status > 0)
            {
                txtStatus.Text = "Card personalization was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Card personalization successful";
            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnAuthSL1_Click(object sender, EventArgs e)
        {
            DL_STATUS status;

            byte[] sl1_auth_key = new byte[16];

            byte key_index = 0;

            if (rbChangeAuthPK.Checked)
            {
                if (txtAuthSL1AuthKey.TextLength != 32)
                {
                    txtStatus.Text = "SL1 card authentication key must be 16 bytes long";
                    return;
                }

                sl1_auth_key = StringToByteArray(txtAuthSL1AuthKey.Text);
                status = (UInt32)uFCoder.MFP_AesAuthSecurityLevel1_PK(sl1_auth_key);

                if (status > 0)
                {
                    txtStatus.Text = "AES authentication on SL1 was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "AES authentication on SL1 successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
            }
            else
            {
                key_index = Byte.Parse(cbAuthSL1ReaderKeyIndex.Text);

                status = (UInt32)uFCoder.MFP_AesAuthSecurityLevel1(key_index);

                if (status > 0)
                {
                    txtStatus.Text = "AES authentication on SL1 was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "AES authentication on SL1 successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
            }

        }

        private void btnSwitchSL3_Click(object sender, EventArgs e)
        {
            DL_STATUS status;

            byte[] sl3_sw_key = new byte[16];
            byte key_index = 0;

            if (rbChangeAuthPK.Checked)
            {
                if (txtSwitchSL3AESkey.TextLength != 32)
                {
                    txtStatus.Text = "Level 3 switch key must be 16 bytes long";
                    return;
                }

                sl3_sw_key = StringToByteArray(txtSwitchSL3AESkey.Text);

                status = (UInt32)uFCoder.MFP_SwitchToSecurityLevel3_PK(sl3_sw_key);

                if (status > 0)
                {
                    txtStatus.Text = "Switch to SL3 was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "Switch to SL3 successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
            }
            else
            {
                key_index = Byte.Parse(cbSwitchSL3ReaderKeyIndex.Text);

                status = (UInt32)uFCoder.MFP_SwitchToSecurityLevel3(key_index);

                if (status > 0)
                {
                    txtStatus.Text = "Switch to SL3 was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "Switch to SL3 successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
            }

        }

        private void btnChangeMasterKey_Click(object sender, EventArgs e)
        {
            DL_STATUS status;

            byte[] old_master_key = new byte[16];
            byte[] new_master_key = new byte[16];
            byte key_index = 0;

            if (rbChangeAuthPK.Checked)
            {
                if (txtChangeMasterOldKey.TextLength != 32)
                {
                    txtStatus.Text = "Old master key must be 16 bytes long";
                    return;
                }

                if (txtChangeMasterNewKey.TextLength != 32)
                {
                    txtStatus.Text = "New master key must be 16 bytes long";
                    return;
                }

                old_master_key = StringToByteArray(txtChangeMasterOldKey.Text);

                new_master_key = StringToByteArray(txtChangeMasterNewKey.Text);

                status = (UInt32)uFCoder.MFP_ChangeMasterKey_PK(old_master_key, new_master_key);

                if (status > 0)
                {
                    txtStatus.Text = "Master key change was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "Master key change successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
            }
            else
            {
                if (txtChangeMasterNewKeyRK.TextLength != 32)
                {
                    txtStatus.Text = "New master key must be 16 bytes long";
                    return;
                }

                new_master_key = StringToByteArray(txtChangeMasterNewKeyRK.Text);

                key_index = Byte.Parse(cbChangeMasterReaderKeyIndex.Text);

                status = (UInt32)uFCoder.MFP_ChangeMasterKey(key_index, new_master_key);

                if (status > 0)
                {
                    txtStatus.Text = "Master key change was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "Master key change successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
            }
        }

        private void btnChangeConfigurationKey_Click(object sender, EventArgs e)
        {
            DL_STATUS status;

            byte[] old_config_key = new byte[16];
            byte[] new_config_key = new byte[16];
            byte key_index = 0;

            if (rbChangeAuthPK.Checked)
            {
                if (txtChangeMasterOldKey.TextLength != 32)
                {
                    txtStatus.Text = "Old configuration key must be 16 bytes long";
                    return;
                }

                if (txtChangeMasterNewKey.TextLength != 32)
                {
                    txtStatus.Text = "New configuration key must be 16 bytes long";
                    return;
                }

                old_config_key = StringToByteArray(txtChangeConfigOldKey.Text);

                new_config_key = StringToByteArray(txtChangeConfigNewKey.Text);

                status = (UInt32)uFCoder.MFP_ChangeConfigurationKey_PK(old_config_key, new_config_key);

                if (status > 0)
                {
                    txtStatus.Text = "Configuration key change was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "Configuration key change successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
            }
            else
            {
                if (txtChangeConfigNewKeyRK.TextLength != 32)
                {
                    txtStatus.Text = "New configuration key must be 16 bytes long";
                    return;
                }

                new_config_key = StringToByteArray(txtChangeConfigNewKeyRK.Text);

                key_index = Byte.Parse(cbChangeMasterReaderKeyIndex.Text);

                status = (UInt32)uFCoder.MFP_ChangeConfigurationKey(key_index, new_config_key);

                if (status > 0)
                {
                    txtStatus.Text = "Configuration key change was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "Configuration key change successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
            }
        }

        private void btnChangeAESSectorKey_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] old_sector_key = new byte[16];
            byte[] new_sector_key = new byte[16];
            byte key_index = 0, sector_nr = 0, auth_mode = 0;

            sector_nr = Byte.Parse(cbChangeSectorSectorNumber.Text);

            if (rbChangeSectorKeyA.Checked)
            {
                auth_mode = (byte)MIFARE_PLUS_AES_AUTHENTICATION.MIFARE_PLUS_AES_AUTHENT1A;
            }
            else if (rbChangeSectorKeyB.Checked)
            {
                auth_mode = (byte)MIFARE_PLUS_AES_AUTHENTICATION.MIFARE_PLUS_AES_AUTHENT1B;
            }
            else
            {
                txtStatus.Text = "You should select settings AES KEY A or B";
                return;
            }

            if (rbChangeAuthPK.Checked)
            {
                if (txtChangeSectorOldKey.TextLength != 32)
                {
                    txtStatus.Text = "Old sector key must be 16 bytes long";
                    return;
                }

                if (txtChangeSectorNewKey.TextLength != 32)
                {
                    txtStatus.Text = "New sector key must be 16 bytes long";
                    return;
                }

                old_sector_key = StringToByteArray(txtChangeSectorOldKey.Text);

                new_sector_key = StringToByteArray(txtChangeSectorNewKey.Text);

                status = (UInt32)uFCoder.MFP_ChangeSectorKey_PK(sector_nr, auth_mode, old_sector_key, new_sector_key);

                if (status > 0)
                {
                    txtStatus.Text = "Sector key change was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "Sector key change successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

            }
            else if (rbChangeAuthRK.Checked)
            {
                if (txtChangeSectorNewKeyRK.TextLength != 32)
                {
                    txtStatus.Text = "New sector key must be 16 bytes long";
                    return;
                }

                new_sector_key = StringToByteArray(txtChangeConfigNewKeyRK.Text);

                key_index = Byte.Parse(cbChangeSectorKeyReaderIndex.Text);

                status = (UInt32)uFCoder.MFP_ChangeSectorKey(sector_nr, auth_mode, key_index, new_sector_key);

                if (status > 0)
                {
                    txtStatus.Text = "Sector key change was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "Sector key change successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

            }

        }

        private void btnFieldConfigurationSet_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] config_key = new byte[16];
            byte key_index = 0, rid_use = 0, prox_check_use = 0;

            //Proximity check for X and EV1 card is not implemented yet
            prox_check_use = 0;

            //setting usage of random id or uid
            if (rbFieldConfigUseRandomID.Checked)
            {
                rid_use = 1;
            }
            else if (rbFieldConfigUseUID.Checked)
            {
                rid_use = 0;
            }

            if (rbChangeAuthPK.Checked)
            {

                if (txtFieldConfigKey.TextLength != 32)
                {
                    txtStatus.Text = "Field configuration key must be 16 bytes long";
                    return;
                }

                config_key = StringToByteArray(txtFieldConfigKey.Text);

                status = (UInt32)uFCoder.MFP_FieldConfigurationSet_PK(config_key, rid_use, prox_check_use);

                if (status > 0)
                {
                    txtStatus.Text = "Field configuration set was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "Field configuration set successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

            }
            else if (rbChangeAuthRK.Checked)
            {
                key_index = Byte.Parse(cbFieldConfigReaderKeyIndex.Text);

                status = (UInt32)uFCoder.MFP_FieldConfigurationSet(key_index, rid_use, prox_check_use);

                if (status > 0)
                {
                    txtStatus.Text = "Field configuration set was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "Field configuration set successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
            }

        }

        private void btnGetCardUID_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] vc_enc_key = new byte[16];
            byte[] vc_mac_key = new byte[16];
            byte key_index_enc = 0, key_index_mac = 0, uid_len = 0;
            byte[] uid = new byte[10];

            if (rbChangeAuthPK.Checked)
            {
                if (txtGetCardUIDENCKey.TextLength != 32)
                {
                    txtStatus.Text = "VC polling ENC key must be 16 bytes long";
                    return;
                }

                if (txtGetCardUIDMACKey.TextLength != 32)
                {
                    txtStatus.Text = "VC polling MAC key must be 16 bytes long";
                    return;
                }

                vc_enc_key = StringToByteArray(txtGetCardUIDENCKey.Text);

                vc_mac_key = StringToByteArray(txtGetCardUIDMACKey.Text);

                status = (UInt32)uFCoder.MFP_GetUid_PK(vc_enc_key, vc_mac_key, uid, out uid_len);

                if (status > 0)
                {
                    txtStatus.Text = "Get UID was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }
                txtStatus.Text = "Get UID was successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
                txtUID_Get.Text = BitConverter.ToString(uid).Replace("-", ":");

            }
            else if (rbChangeAuthRK.Checked)
            {
                key_index_enc = Byte.Parse(cbGetCardUIDENCKeyRK.Text);

                key_index_mac = Byte.Parse(cbGetCardUIDMACKeyRK.Text);

                status = (UInt32)uFCoder.MFP_GetUid(key_index_enc, key_index_mac, uid, out uid_len);

                if (status > 0)
                {
                    txtStatus.Text = "Get UID was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }
                txtStatus.Text = "Get UID was successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
                txtUID_Get.Text = BitConverter.ToString(uid).Replace("-", ":");

            }
        }

        private void btnChangeVCPollingENCKey_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] config_key = new byte[16];
            byte[] new_vc_enc_key = new byte[16];
            byte key_index = 0;

            if (rbChangeAuthPK.Checked)
            {
                if (txtChangeVCPollingENCConfigKey.TextLength != 32)
                {
                    txtStatus.Text = "Card configuration key must be 16 bytes long";
                    return;
                }

                if (txtChangeVCPollingENCNewKey.TextLength != 32)
                {
                    txtStatus.Text = "New VC polling ENC key must be 16 bytes long";
                    return;
                }

                config_key = StringToByteArray(txtChangeVCPollingENCConfigKey.Text);

                new_vc_enc_key = StringToByteArray(txtChangeVCPollingENCNewKey.Text);

                status = (UInt32)uFCoder.MFP_ChangeVcPollingEncKey_PK(config_key, new_vc_enc_key);

                if (status > 0)
                {
                    txtStatus.Text = "VC polling ENC key change was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "VC polling ENC key change was successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

            }
            else if (rbChangeAuthRK.Checked)
            {
                key_index = Byte.Parse(cbChangeVCPollingENCReaderKeyIndex.Text);

                if (txtChangeVCPollingENCNewKeyRK.TextLength != 32)
                {
                    txtStatus.Text = "New VC polling ENC key must be 16 bytes long";
                    return;
                }

                new_vc_enc_key = StringToByteArray(txtChangeVCPollingENCNewKeyRK.Text);

                status = (UInt32)uFCoder.MFP_ChangeVcPollingEncKey(key_index, new_vc_enc_key);

                if (status > 0)
                {
                    txtStatus.Text = "VC polling ENC key change was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "VC polling ENC key change was successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

            }

        }

        private void btnChangeVCPollingMACKey_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] config_key = new byte[16];
            byte[] new_vc_mac_key = new byte[16];
            byte key_index = 0;

            if (rbChangeAuthPK.Checked)
            {
                if (txtChangeVCPollingMACConfigKey.TextLength != 32)
                {
                    txtStatus.Text = "Card configuration key must be 16 bytes long";
                    return;
                }

                if (txtChangeVCPollingMACNewKey.TextLength != 32)
                {
                    txtStatus.Text = "New VC polling MAC key must be 16 bytes long";
                    return;
                }

                config_key = StringToByteArray(txtChangeVCPollingMACConfigKey.Text);

                new_vc_mac_key = StringToByteArray(txtChangeVCPollingMACNewKey.Text);

                status = (UInt32)uFCoder.MFP_ChangeVcPollingMacKey_PK(config_key, new_vc_mac_key);

                if (status > 0)
                {
                    txtStatus.Text = "VC polling MAC key change was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "VC polling MAC key change was successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

            }
            else if (rbChangeAuthRK.Checked)
            {
                key_index = Byte.Parse(cbChangeVCPollingMACReaderKeyIndex.Text);

                if (txtChangeVCPollingMACNewKeyRK.TextLength != 32)
                {
                    txtStatus.Text = "New VC polling MAC key must be 16 bytes long";
                    return;
                }

                new_vc_mac_key = StringToByteArray(txtChangeVCPollingMACNewKeyRK.Text);

                status = (UInt32)uFCoder.MFP_ChangeVcPollingMacKey(key_index, new_vc_mac_key);

                if (status > 0)
                {
                    txtStatus.Text = "VC polling MAC key change was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "VC polling MAC key change was successful";
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

            }
        }

        private void btnCrypto1KeyInput_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] crypto_key = new byte[6];
            byte key_index = 0;

            if (txtCrypto1Key.TextLength != 12)
            {
                txtStatus.Text = "Crypto key must be 6 bytes long";
                return;
            }

            crypto_key = StringToByteArray(txtCrypto1Key.Text);

            key_index = Byte.Parse(cbCrpytoReaderIndex.Text);

            status = (UInt32)uFCoder.ReaderKeyWrite(crypto_key, key_index);
            if (status > 0)
            {
                txtStatus.Text = "CRYPTO 1 key writing was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "CRYPTO 1 key writing was successful";
            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);


        }

        private void btnAesKeyInput_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] aes_key = new byte[16];
            byte key_index = 0;

            if (txtAESKey.TextLength != 32)
            {
                txtStatus.Text = "AES key must be 16 bytes long";
                return;
            }

            aes_key = StringToByteArray(txtAESKey.Text);

            key_index = Byte.Parse(cbAESIndex.Text);

            status = (UInt32)uFCoder.uFR_int_DesfireWriteAesKey(key_index, aes_key);

            if (status > 0)
            {
                txtStatus.Text = "AES key writing was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "AES key writing was successful";
            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnUnlockReader_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            String password = "";

            if (txtUnlockPassword.TextLength != 8)
            {
                txtStatus.Text = "Password must be 8 characters long";
                return;
            }

            password = txtUnlockPassword.Text;

            status = (UInt32)uFCoder.ReaderKeysUnlock(password.ToCharArray());

            if (status > 0)
            {
                txtStatus.Text = "Reader unlocking was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Reader unlocking was successful";
            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);


        }

        private void btnLockReader_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            String password = "";

            if (txtLockPassword.TextLength != 8)
            {
                txtStatus.Text = "Password must be 8 characters long";
                return;
            }

            password = txtLockPassword.Text;

            status = (UInt32)uFCoder.ReaderKeysLock(password.ToCharArray());

            if (status > 0)
            {
                txtStatus.Text = "Reader locking was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Reader locking was successful";
            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void TabPage6_Click(object sender, EventArgs e)
        {

        }

        private void btnBlockReadPK_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte dl_card_type = 0;
            byte auth_mode = 0, block_address = 0;
            byte[] crypto_key = new byte[6];
            byte[] aes_key = new byte[16];
            byte[] block_data = new byte[16];

            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            //Using AES or CRYPTO key depending on following check of card type

            if (((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
             ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1))
            {
                //" (1) - Provided CRYPTO 1 key\n PK"
                if (rbBlockReadKeyAPK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A; // auth mode check

                }
                else if (rbBlockReadKeyBPK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
                }

                if (txtBlockReadKeyPK.TextLength != 12)
                {
                    txtStatus.Text = "This card uses CRYPTO 1 key that should be 6 bytes long";
                    return;
                }

                crypto_key = StringToByteArray(txtBlockReadKeyPK.Text);

                block_address = Byte.Parse(cbBlockReadBlockNrPK.Text);

                status = (UInt32)uFCoder.BlockRead_PK(block_data, block_address, auth_mode, crypto_key);

                if (status > 0)
                {
                    txtStatus.Text = "Block read was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "Block read was successful.\nBlock data: ";
                txtStatus.Text += BitConverter.ToString(block_data).Replace("-", ":");
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

            }
            else
            {
                //" (2) - Provided AES key\n PK"
                if (rbBlockReadKeyAPK.Checked)
                {
                    auth_mode = (byte)MIFARE_PLUS_AES_AUTHENTICATION.MIFARE_PLUS_AES_AUTHENT1A; // auth mode check
                }
                else if (rbBlockReadKeyBPK.Checked)
                {
                    auth_mode = (byte)MIFARE_PLUS_AES_AUTHENTICATION.MIFARE_PLUS_AES_AUTHENT1B;
                }

                if (txtBlockReadKeyPK.TextLength != 32)
                {
                    txtStatus.Text = "This card uses AES key that should be 16 bytes long";
                    return;
                }

                aes_key = StringToByteArray(txtBlockReadKeyPK.Text);

                block_address = Byte.Parse(cbBlockReadBlockNrPK.Text);

                status = (UInt32)uFCoder.BlockRead_PK(block_data, block_address, auth_mode, aes_key);

                if (status > 0)
                {
                    txtStatus.Text = "Block read was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "Block read was successful.\nBlock data: ";
                txtStatus.Text += BitConverter.ToString(block_data).Replace("-", ":");
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
            }

        }

        private void btnBlockReadRK_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte dl_card_type = 0;
            byte auth_mode = 0, block_address = 0;
            byte crypto_key_nr = 0;
            byte aes_key_nr = 0;
            byte[] block_data = new byte[16];

            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            //Using AES or CRYPTO key depending on following check of card type

            if (((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
             ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1))
            {
                //" (1) - Reader CRYPTO 1 key\n RK"
                if (rbBlockReadKeyARK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A; // auth mode check

                }
                else if (rbBlockReadKeyBRK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
                }

                crypto_key_nr = Byte.Parse(cbBlockReadKeyRK.Text);

                block_address = Byte.Parse(cbBlockReadBlockNrRK.Text);

                status = (UInt32)uFCoder.BlockRead(block_data, block_address, auth_mode, crypto_key_nr);

                if (status > 0)
                {
                    txtStatus.Text = "Block read was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "Block read was successful.\nBlock data: ";
                txtStatus.Text += BitConverter.ToString(block_data).Replace("-", ":");
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

            }
            else
            {
                //" (2) - Reader AES key\n RK"
                if (rbBlockReadKeyARK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A; ; // auth mode check
                }
                else if (rbBlockReadKeyBRK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
                }

                aes_key_nr = Byte.Parse(cbBlockReadKeyRK.Text);

                block_address = Byte.Parse(cbBlockReadBlockNrRK.Text);

                status = (UInt32)uFCoder.BlockRead(block_data, block_address, auth_mode, aes_key_nr);

                if (status > 0)
                {
                    txtStatus.Text = "Block read was NOT successful";
                    toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                    return;
                }

                txtStatus.Text = "Block read was successful.\nBlock data: ";
                txtStatus.Text += BitConverter.ToString(block_data).Replace("-", ":");
                toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

            }

        }

        private void btnBlockReadAKM1_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte dl_card_type = 0;
            byte auth_mode = 0, block_address = 0;
            byte[] block_data = new byte[16];

            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            //" (1) - Provided CRYPTO 1 key\n AKM1"
            if (rbBlockReadKeyAAKM1.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A; // auth mode check

            }
            else if (rbBlockReadKeyBAKM1.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            block_address = Byte.Parse(cbBlockReadBlockNrAKM1.Text);

            status = (UInt32)uFCoder.BlockRead_AKM1(block_data, block_address, auth_mode);

            if (status > 0)
            {
                txtStatus.Text = "Block read was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Block read was successful.\nBlock data: ";
            txtStatus.Text += BitConverter.ToString(block_data).Replace("-", ":");
            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnBlockReadAKM2_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte dl_card_type = 0;
            byte auth_mode = 0, block_address = 0;
            byte[] block_data = new byte[16];

            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            ////////////////AKM2/////////////////////"
            if (rbBlockReadKeyAAKM2.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A; // auth mode check

            }
            else if (rbBlockReadKeyBAKM2.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            block_address = Byte.Parse(cbBlockReadBlockNrAKM2.Text);

            status = (UInt32)uFCoder.BlockRead_AKM2(block_data, block_address, auth_mode);

            if (status > 0)
            {
                txtStatus.Text = "Block read was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Block read was successful.\nBlock data: ";
            txtStatus.Text += BitConverter.ToString(block_data).Replace("-", ":");
            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

        }


        private void btnBlockInSectorReadPK_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] block_data = new byte[16];
            byte[] sector_key = new byte[16];
            byte sector_nr = 0, block_nr = 0, auth_mode = 0;
            byte dl_card_type = 0;
            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
             ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1))
            {
                if (txtBlockInSectorReadKeyPK.TextLength != 12)
                {
                    txtStatus.Text = "This card uses CRYPTO 1 key that should be 6 bytes long";
                    return;
                }

                sector_key = StringToByteArray(txtBlockInSectorReadKeyPK.Text);

                if (rbBlockInSectorReadKeyAPK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

                }
                else if (rbBlockInSectorReadKeyBPK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
                }

            }
            else
            {
                if (txtBlockInSectorReadKeyPK.TextLength != 32)
                {
                    txtStatus.Text = "This card uses AES key that should be 16 bytes long";
                    return;
                }

                sector_key = StringToByteArray(txtBlockInSectorReadKeyPK.Text);

                if (rbBlockInSectorReadKeyAPK.Checked)
                {
                    auth_mode = (byte)MIFARE_PLUS_AES_AUTHENTICATION.MIFARE_PLUS_AES_AUTHENT1A;
                }
                else if (rbBlockInSectorReadKeyBPK.Checked)
                {
                    auth_mode = (byte)MIFARE_PLUS_AES_AUTHENTICATION.MIFARE_PLUS_AES_AUTHENT1B;
                }
            }

            sector_nr = Byte.Parse(cbBlockInSectorSectorNrPK.Text);

            block_nr = Byte.Parse(cbBlockInSectorBlockNrPK.Text);


            status = (UInt32)uFCoder.BlockInSectorRead_PK(block_data, sector_nr, block_nr, auth_mode, sector_key);

            if (status > 0)
            {
                txtStatus.Text = "Block read was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Block read was successful.\nBlock data: ";
            txtStatus.Text += BitConverter.ToString(block_data).Replace("-", ":");
            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

        }

        private void bnBlockInSectorReadRK_Click(object sender, EventArgs e)
        {
            //RK
            DL_STATUS status;
            byte[] block_data = new byte[16];
            byte sector_nr = 0, block_nr = 0, auth_mode = 0, key_nr = 0;
            byte dl_card_type = 0;
            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }


            if (rbBlockInSectorReadKeyARK.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;
            }
            else if (rbBlockInSectorReadKeyBRK.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            key_nr = Byte.Parse(cbBlockInSectorReadKeyRK.Text);

            sector_nr = Byte.Parse(cbBlockInSectorSectorNrRK.Text);

            block_nr = Byte.Parse(cbBlockInSectorBlockNrRK.Text);

            status = (UInt32)uFCoder.BlockInSectorRead(block_data, sector_nr, block_nr, auth_mode, key_nr);

            if (status > 0)
            {
                txtStatus.Text = "Block read was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Block read was successful.\nBlock data: ";
            txtStatus.Text += BitConverter.ToString(block_data).Replace("-", ":");
            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnBlockInSectoReadAKM1_Click(object sender, EventArgs e)
        {
            //AKM1
            DL_STATUS status;
            byte[] block_data = new byte[16];
            byte sector_nr = 0, block_nr = 0, auth_mode = 0;
            byte dl_card_type = 0;
            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (rbBlockInSectorReadKeyAAKM1.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;
            }
            else if (rbBlockInSectorReadKeyBAKM1.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            sector_nr = Byte.Parse(cbBlockInSectorSectorNrAKM1.Text);

            block_nr = Byte.Parse(cbBlockInSectorBlockNrAKM1.Text);

            status = (UInt32)uFCoder.BlockInSectorRead_AKM1(block_data, sector_nr, block_nr, auth_mode);

            if (status > 0)
            {
                txtStatus.Text = "Block read was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Block read was successful.\nBlock data: ";
            txtStatus.Text += BitConverter.ToString(block_data).Replace("-", ":");
            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }


        private void btnBlockInSectorReadAKM2_Click(object sender, EventArgs e)
        {
            //AKM2
            DL_STATUS status;
            byte[] block_data = new byte[16];
            byte sector_nr = 0, block_nr = 0, auth_mode = 0;
            byte dl_card_type = 0;

            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (rbBlockInSectorReadKeyAAKM2.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;
            }
            else if (rbBlockInSectorReadKeyBAKM2.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            sector_nr = Byte.Parse(cbBlockInSectorSectorNrAKM2.Text);

            block_nr = Byte.Parse(cbBlockInSectorBlockNrAKM2.Text);

            status = (UInt32)uFCoder.BlockInSectorRead_AKM2(block_data, sector_nr, block_nr, auth_mode);

            if (status > 0)
            {
                txtStatus.Text = "Block read was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Block read was successful.\nBlock data: ";
            txtStatus.Text += BitConverter.ToString(block_data).Replace("-", ":");
            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnLinearReadPK_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] linear_data = new byte[3440];
            byte[] sector_key = new byte[16];
            ushort linear_address = 0, linear_length = 0, ret_bytes = 0;
            byte dl_card_type = 0, auth_mode = 0;


            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }


            if (((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
             ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1))
            {
                if (txtLinearReadKeyPK.TextLength != 12)
                {
                    txtStatus.Text = "This card uses CRYPTO 1 key that should be 6 bytes long";
                    return;
                }

                sector_key = StringToByteArray(txtLinearReadKeyPK.Text);

                if (rbLinearReadKeyAPK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

                }
                else if (rbLinearReadKeyBPK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
                }
            }
            else
            {
                if (txtLinearReadKeyPK.TextLength != 32)
                {
                    txtStatus.Text = "This card uses AES key that should be 16 bytes long";
                    return;
                }

                sector_key = StringToByteArray(txtLinearReadKeyPK.Text);

                if (rbLinearReadKeyAPK.Checked)
                {
                    auth_mode = (byte)MIFARE_PLUS_AES_AUTHENTICATION.MIFARE_PLUS_AES_AUTHENT1A;
                }
                else if (rbLinearReadKeyBPK.Checked)
                {
                    auth_mode = (byte)MIFARE_PLUS_AES_AUTHENTICATION.MIFARE_PLUS_AES_AUTHENT1B;
                }
            }

            linear_address = Convert.ToUInt16(txtLinearAddressPK.Text);

            linear_length = Convert.ToUInt16(txtBytesForReadPK.Text);

            status = (UInt32)uFCoder.LinearRead_PK(linear_data, linear_address, linear_length, out ret_bytes, auth_mode, sector_key);

            if (status > 0)
            {
                txtStatus.Text = "Linear read was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Linear read was successful.\nBlock data: ";

            byte[] write_data = new byte[ret_bytes];

            Array.Copy(linear_data, write_data, ret_bytes);

            txtStatus.Text += BitConverter.ToString(write_data).Replace("-", ":");

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnLinearReadRK_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] linear_data = new byte[3440];
            byte sector_key_index = 0;
            ushort linear_address = 0, linear_length = 0, ret_bytes = 0;
            byte dl_card_type = 0, auth_mode = 0;


            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (rbLinearReadKeyARK.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

            }
            else if (rbLinearReadKeyBRK.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            sector_key_index = Byte.Parse(cbLinearReadReaderKeyRK.Text);

            linear_address = Convert.ToUInt16(txtLinearAddressRK.Text);

            linear_length = Convert.ToUInt16(txtBytesForReadRK.Text);

            status = (UInt32)uFCoder.LinearRead(linear_data, linear_address, linear_length, out ret_bytes, auth_mode, sector_key_index);

            if (status > 0)
            {
                txtStatus.Text = "Linear read was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Linear read was successful.\nBlock data: ";

            byte[] write_data = new byte[ret_bytes];

            Array.Copy(linear_data, write_data, ret_bytes);

            txtStatus.Text += BitConverter.ToString(write_data).Replace("-", ":");

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnLinearReadAKM1_Click(object sender, EventArgs e)
        {
            //AKM1

            DL_STATUS status;
            byte[] linear_data = new byte[3440];
            ushort linear_address = 0, linear_length = 0, ret_bytes = 0;
            byte dl_card_type = 0, auth_mode = 0;


            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (rbLinearReadKeyAAKM1.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

            }
            else if (rbLinearReadKeyBAKM1.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            linear_address = Convert.ToUInt16(txtLinearAddressAKM1.Text);

            linear_length = Convert.ToUInt16(txtBytesForReadAKM1.Text);

            status = (UInt32)uFCoder.LinearRead_AKM1(linear_data, linear_address, linear_length, out ret_bytes, auth_mode);

            if (status > 0)
            {
                txtStatus.Text = "Linear read was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Linear read was successful.\nBlock data: ";

            byte[] write_data = new byte[ret_bytes];

            Array.Copy(linear_data, write_data, ret_bytes);

            txtStatus.Text += BitConverter.ToString(write_data).Replace("-", ":");

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

        }

        private void btnLinearReadAKM2_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] linear_data = new byte[3440];
            ushort linear_address = 0, linear_length = 0, ret_bytes = 0;
            byte dl_card_type = 0, auth_mode = 0;


            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (rbLinearReadKeyAAKM2.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

            }
            else if (rbLinearReadKeyBAKM2.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            linear_address = Convert.ToUInt16(txtLinearAddressAKM2.Text);

            linear_length = Convert.ToUInt16(txtBytesForReadAKM2.Text);

            status = (UInt32)uFCoder.LinearRead_AKM2(linear_data, linear_address, linear_length, out ret_bytes, auth_mode);

            if (status > 0)
            {
                txtStatus.Text = "Linear read was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Linear read was successful.\nBlock data: ";

            byte[] write_data = new byte[ret_bytes];

            Array.Copy(linear_data, write_data, ret_bytes);

            txtStatus.Text += BitConverter.ToString(write_data).Replace("-", ":");

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnBlockWritePK_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte dl_card_type = 0, auth_mode = 0, block_nr = 0;
            byte[] sector_key = new byte[16];
            byte[] block_data = new byte[16];


            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
             ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1))
            {
                if (txtBlockWriteKeyPK.TextLength != 12)
                {
                    txtStatus.Text = "This card uses CRYPTO 1 key that should be 6 bytes long";
                    return;
                }

                sector_key = StringToByteArray(txtBlockWriteKeyPK.Text);

                if (rbBlockWriteKeyAPK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

                }
                else if (rbBlockWriteKeyBPK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
                }
            }
            else
            {
                if (txtBlockWriteKeyPK.TextLength != 32)
                {
                    txtStatus.Text = "This card uses AES key that should be 16 bytes long";
                    return;
                }

                sector_key = StringToByteArray(txtBlockWriteKeyPK.Text);

                if (rbBlockWriteKeyAPK.Checked)
                {
                    auth_mode = (byte)MIFARE_PLUS_AES_AUTHENTICATION.MIFARE_PLUS_AES_AUTHENT1A;
                }
                else if (rbBlockWriteKeyBPK.Checked)
                {
                    auth_mode = (byte)MIFARE_PLUS_AES_AUTHENTICATION.MIFARE_PLUS_AES_AUTHENT1B;
                }
            }


            if (txtBlockData.TextLength > 32 || txtBlockData.TextLength < 1)
            {
                txtStatus.Text = "Data for Block Write must be max 16 bytes long";
                return;
            }

            block_data = StringToByteArray(txtBlockData.Text);

            block_nr = Byte.Parse(cbBlockWriteBlockNrPK.Text);


            status = (UInt32)uFCoder.BlockWrite_PK(block_data, block_nr, auth_mode, sector_key);

            if (status > 0)
            {
                txtStatus.Text = "Block write was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Block write was successful. ";

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

        }

        private void btnBlockWriteRK_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte dl_card_type = 0, auth_mode = 0, block_nr = 0;
            byte key_nr = 0;
            byte[] block_data = new byte[16];

            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (rbBlockWriteKeyARK.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

            }
            else if (rbBlockWriteKeyBRK.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            if (txtBlockData.TextLength > 32 || txtBlockData.TextLength < 1)
            {
                txtStatus.Text = "Data for Block Write must be max 16 bytes long";
                return;
            }

            block_data = StringToByteArray(txtBlockData.Text);

            block_nr = Byte.Parse(cbBlockWriteBlockNrRK.Text);

            key_nr = Byte.Parse(cbBlockWriteKeyIndexRK.Text);

            status = (UInt32)uFCoder.BlockWrite(block_data, block_nr, auth_mode, key_nr);

            if (status > 0)
            {
                txtStatus.Text = "Block write was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Block write was successful. ";

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

        }

        private void btnBlockWriteAKM1_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte dl_card_type = 0, auth_mode = 0, block_nr = 0;

            byte[] block_data = new byte[16];

            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (rbBlockWriteKeyAAKM1.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

            }
            else if (rbBlockWriteKeyBAKM1.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            if (txtBlockData.TextLength > 32 || txtBlockData.TextLength < 1)
            {
                txtStatus.Text = "Data for Block Write must be max 16 bytes long";
                return;
            }

            block_data = StringToByteArray(txtBlockData.Text);

            block_nr = Byte.Parse(cbBlockWriteBlockNrAKM1.Text);

            status = (UInt32)uFCoder.BlockWrite_AKM1(block_data, block_nr, auth_mode);

            if (status > 0)
            {
                txtStatus.Text = "Block write was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Block write was successful. ";

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnBlockWriteAKM2_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte dl_card_type = 0, auth_mode = 0, block_nr = 0;

            byte[] block_data = new byte[16];

            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (rbBlockWriteKeyAAKM2.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

            }
            else if (rbBlockWriteKeyBAKM2.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            if (txtBlockData.TextLength > 32 || txtBlockData.TextLength < 1)
            {
                txtStatus.Text = "Data for Block Write must be max 16 bytes long";
                return;
            }

            block_data = StringToByteArray(txtBlockData.Text);

            block_nr = Byte.Parse(cbBlockWriteBlockNrAKM2.Text);

            status = (UInt32)uFCoder.BlockWrite_AKM2(block_data, block_nr, auth_mode);

            if (status > 0)
            {
                txtStatus.Text = "Block write was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Block write was successful. ";

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnBlockInSectorWritePK_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte dl_card_type = 0, auth_mode = 0, block_nr = 0, sector_nr = 0;
            byte[] sector_key = new byte[16];
            byte[] block_data = new byte[16];


            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
             ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1))
            {
                if (txtBlockInSectorWriteKeyPK.TextLength != 12)
                {
                    txtStatus.Text = "This card uses CRYPTO 1 key that should be 6 bytes long";
                    return;
                }

                sector_key = StringToByteArray(txtBlockInSectorWriteKeyPK.Text);

                if (rbBlockInSectorWriteKeyAPK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

                }
                else if (rbBlockInSectorWriteKeyBPK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
                }
            }
            else
            {
                if (txtBlockInSectorWriteKeyPK.TextLength != 32)
                {
                    txtStatus.Text = "This card uses AES key that should be 16 bytes long";
                    return;
                }

                sector_key = StringToByteArray(txtBlockInSectorWriteKeyPK.Text);

                if (rbBlockInSectorWriteKeyAPK.Checked)
                {
                    auth_mode = (byte)MIFARE_PLUS_AES_AUTHENTICATION.MIFARE_PLUS_AES_AUTHENT1A;
                }
                else if (rbBlockInSectorWriteKeyBPK.Checked)
                {
                    auth_mode = (byte)MIFARE_PLUS_AES_AUTHENTICATION.MIFARE_PLUS_AES_AUTHENT1B;
                }
            }


            if (txtBlockInSectorData.TextLength > 32 || txtBlockInSectorData.TextLength < 1)
            {
                txtStatus.Text = "Data for Block in sector Write must be max 16 bytes long";
                return;
            }

            block_data = StringToByteArray(txtBlockInSectorData.Text);

            block_nr = Byte.Parse(cbBlockInSectorWriteBlockNrPK.Text);

            sector_nr = Byte.Parse(cbBlockInSectorWriteSectorNrPK.Text);


            status = (UInt32)uFCoder.BlockInSectorWrite_PK(block_data, sector_nr, block_nr, auth_mode, sector_key);

            if (status > 0)
            {
                txtStatus.Text = "Block in sector write was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Block in sector write was successful. ";

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

        }

        private void btnBlockInSectorWriteRK_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte dl_card_type = 0, auth_mode = 0, block_nr = 0, sector_nr = 0;
            byte key_nr = 0;
            byte[] block_data = new byte[16];

            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (rbBlockInSectorWriteKeyARK.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

            }
            else if (rbBlockInSectorWriteKeyBRK.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            if (txtBlockInSectorData.TextLength > 32 || txtBlockInSectorData.TextLength < 1)
            {
                txtStatus.Text = "Data for Block in sector Write must be max 16 bytes long";
                return;
            }

            block_data = StringToByteArray(txtBlockInSectorData.Text);

            sector_nr = Byte.Parse(cbBlockInSectorWriteSectorNrRK.Text);

            block_nr = Byte.Parse(cbBlockInSectorWriteBlockNrRK.Text);

            key_nr = Byte.Parse(cbBlockInSectorWriteKeyIndexRK.Text);

            status = (UInt32)uFCoder.BlockInSectorWrite(block_data, sector_nr, block_nr, auth_mode, key_nr);

            if (status > 0)
            {
                txtStatus.Text = "Block in sector write was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Block in sector write was successful. ";

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);

        }

        private void btnBlockInSectorWriteAKM1_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte dl_card_type = 0, auth_mode = 0, block_nr = 0, sector_nr = 0;

            byte[] block_data = new byte[16];

            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (rbBlockInSectorWriteKeyAAKM1.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

            }
            else if (rbBlockInSectorWriteKeyBAKM1.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            if (txtBlockInSectorData.TextLength > 32 || txtBlockInSectorData.TextLength < 1)
            {
                txtStatus.Text = "Data for Block in sector Write must be max 16 bytes long";
                return;
            }

            block_data = StringToByteArray(txtBlockInSectorData.Text);

            sector_nr = Byte.Parse(cbBlockInSectorWriteSectorNrAKM1.Text);

            block_nr = Byte.Parse(cbBlockInSectorWriteBlockNrAKM1.Text);

            status = (UInt32)uFCoder.BlockInSectorWrite_AKM1(block_data, sector_nr, block_nr, auth_mode);

            if (status > 0)
            {
                txtStatus.Text = "Block in sector write was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Block in sector write was successful. ";

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnBlockInSectorWriteAKM2_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte dl_card_type = 0, auth_mode = 0, block_nr = 0, sector_nr = 0;

            byte[] block_data = new byte[16];

            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (rbBlockInSectorWriteKeyAAKM2.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

            }
            else if (rbBlockInSectorWriteKeyBAKM2.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            if (txtBlockInSectorData.TextLength > 32 || txtBlockInSectorData.TextLength < 1)
            {
                txtStatus.Text = "Data for Block in sector Write must be max 16 bytes long";
                return;
            }

            block_data = StringToByteArray(txtBlockInSectorData.Text);

            sector_nr = Byte.Parse(cbBlockInSectorWriteSectorNrAKM2.Text);

            block_nr = Byte.Parse(cbBlockInSectorWriteBlockNrAKM2.Text);

            status = (UInt32)uFCoder.BlockInSectorWrite_AKM1(block_data, sector_nr, block_nr, auth_mode);

            if (status > 0)
            {
                txtStatus.Text = "Block in sector write was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Block in sector write was successful. ";

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnLinearWritePK_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] linear_data = new byte[3440];
            byte[] sector_key = new byte[16];
            ushort linear_address = 0, linear_length = 0, ret_bytes = 0;
            byte dl_card_type = 0, auth_mode = 0;


            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }


            if (((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
             ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1))
            {
                if (txtLinearWriteKeyPK.TextLength != 12)
                {
                    txtStatus.Text = "This card uses CRYPTO 1 key that should be 6 bytes long";
                    return;
                }

                sector_key = StringToByteArray(txtLinearWriteKeyPK.Text);

                if (rbLinearWriteKeyAPK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

                }
                else if (rbLinearWriteKeyBPK.Checked)
                {
                    auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
                }
            }
            else
            {
                if (txtLinearWriteKeyPK.TextLength != 32)
                {
                    txtStatus.Text = "This card uses AES key that should be 16 bytes long";
                    return;
                }

                sector_key = StringToByteArray(txtLinearWriteKeyPK.Text);

                if (rbLinearWriteKeyAPK.Checked)
                {
                    auth_mode = (byte)MIFARE_PLUS_AES_AUTHENTICATION.MIFARE_PLUS_AES_AUTHENT1A;
                }
                else if (rbLinearWriteKeyBPK.Checked)
                {
                    auth_mode = (byte)MIFARE_PLUS_AES_AUTHENTICATION.MIFARE_PLUS_AES_AUTHENT1B;
                }
            }

            linear_address = Convert.ToUInt16(txtLinearWriteAddressPK.Text);

            linear_data = StringToByteArray(txtLinearWriteData.Text);

            linear_length = Convert.ToUInt16(linear_data.Length);

            status = (UInt32)uFCoder.LinearWrite_PK(linear_data, linear_address, linear_length, out ret_bytes, auth_mode, sector_key);

            if (status > 0)
            {
                txtStatus.Text = "Linear write was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Linear write was successful.";
            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnLinearWriteRK_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] linear_data = new byte[3440];
            byte sector_key_index = 0;
            ushort linear_address = 0, linear_length = 0, ret_bytes = 0;
            byte dl_card_type = 0, auth_mode = 0;


            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (rbLinearWriteKeyARK.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

            }
            else if (rbLinearWriteKeyBRK.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            linear_data = StringToByteArray(txtLinearWriteData.Text);

            sector_key_index = Byte.Parse(cbLinearWriteKeyIndexRK.Text);

            linear_address = Convert.ToUInt16(txtLinearWriteAddressRK.Text);

            linear_length = Convert.ToUInt16(txtLinearWriteData.TextLength);

            status = (UInt32)uFCoder.LinearWrite(linear_data, linear_address, linear_length, out ret_bytes, auth_mode, sector_key_index);

            if (status > 0)
            {
                txtStatus.Text = "Linear write was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Linear write was successful. ";

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnLinearWriteAKM1_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] linear_data = new byte[3440];

            ushort linear_address = 0, linear_length = 0, ret_bytes = 0;
            byte dl_card_type = 0, auth_mode = 0;


            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (rbLinearWriteKeyAAKM1.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

            }
            else if (rbLinearWriteKeyBAKM1.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            linear_data = StringToByteArray(txtLinearWriteData.Text);

            linear_address = Convert.ToUInt16(txtLinearWriteAddressAKM1.Text);

            linear_length = Convert.ToUInt16(txtLinearWriteData.TextLength);

            status = (UInt32)uFCoder.LinearWrite_AKM1(linear_data, linear_address, linear_length, out ret_bytes, auth_mode);

            if (status > 0)
            {
                txtStatus.Text = "Linear write was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Linear write was successful. ";

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

        private void btnLinearWriteAKM2_Click(object sender, EventArgs e)
        {
            DL_STATUS status;
            byte[] linear_data = new byte[3440];

            ushort linear_address = 0, linear_length = 0, ret_bytes = 0;
            byte dl_card_type = 0, auth_mode = 0;


            status = (UInt32)uFCoder.GetDlogicCardType(out dl_card_type);

            if (status > 0)
            {
                txtStatus.Text = "Communication with card failed.";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            if (!(((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_4K_SL1 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL1) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_2K_SL3) ||
              ((DLOGIC_CARD_TYPE)dl_card_type >= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_S_2K_SL3 && (DLOGIC_CARD_TYPE)dl_card_type <= DLOGIC_CARD_TYPE.DL_MIFARE_PLUS_EV1_4K_SL3)))
            {
                txtStatus.Text = "Card is not in security level 1 or 3 mode";
                return;
            }

            if (rbLinearWriteKeyAAKM2.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1A;

            }
            else if (rbLinearWriteKeyBAKM2.Checked)
            {
                auth_mode = (byte)MIFARE_AUTHENTICATION.MIFARE_AUTHENT1B;
            }

            linear_data = StringToByteArray(txtLinearWriteData.Text);

            linear_address = Convert.ToUInt16(txtLinearWriteAddressAKM2.Text);

            linear_length = Convert.ToUInt16(txtLinearWriteData.TextLength);

            status = (UInt32)uFCoder.LinearWrite_AKM2(linear_data, linear_address, linear_length, out ret_bytes, auth_mode);

            if (status > 0)
            {
                txtStatus.Text = "Linear write was NOT successful";
                toolStripStatusLabel1.Text = "Error: " + uFCoder.status2str((uFR.DL_STATUS)status);
                return;
            }

            txtStatus.Text = "Linear write was successful. ";

            toolStripStatusLabel1.Text = "Success: " + uFCoder.status2str((uFR.DL_STATUS)status);
        }

    }
}