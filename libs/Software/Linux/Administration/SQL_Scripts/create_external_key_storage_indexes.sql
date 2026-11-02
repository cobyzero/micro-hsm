CREATE INDEX hsm_keys_key_name_idx ON hsm_keys(key_name);
CREATE INDEX hsm_keys_key_group_idx ON hsm_keys(key_group);
CREATE INDEX hsm_keys_key_spec_idx ON hsm_keys(key_spec);
CREATE INDEX hsm_keys_key_id_idx ON hsm_keys(key_id);
CREATE INDEX hsm_keys_unique_id_idx ON hsm_keys(unique_id);

CREATE INDEX hsm_str_attrs_key_id_idx ON hsm_str_attrs(key_id);
CREATE INDEX hsm_str_attrs_att_id_att_value_idx ON hsm_str_attrs(att_id, att_value);

CREATE INDEX hsm_bin_attrs_key_id_idx ON hsm_bin_attrs(key_id);
CREATE INDEX hsm_bin_attrs_att_id_att_value_idx ON hsm_bin_attrs(att_id, att_value);

CREATE INDEX hsm_int_attrs_key_id_idx ON hsm_int_attrs(key_id);
CREATE INDEX hsm_int_attrs_att_id_att_value_idx ON hsm_int_attrs(att_id, att_value);