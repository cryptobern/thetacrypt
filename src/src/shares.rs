use mircal_core::bls12381::ecp::ECP;


pub trait ECShare {
    fn get_id(&self) -> u8;

    fn get_data(&self) -> ECP;
}


fn interpolate_exp(shares: &Vec<DecryptionShare>) -> ECP2 { 
    let ids:Vec<u8> = (0..shares.len()).map(|x| shares[x].id).collect();
    let mut rG = ECP2::new();

    for i in 0..shares.len() {
        let l = lagrange_coeff(&ids, shares[i].id as isize);
        let mut ui = shares[i].data.clone();
        ui = ui.mul(&l);
        if i == 0 {
            rG = ui;
        } else {
            rG.add(&ui);
        }
    }

    rG
}

fn interpolate(shares: Vec<BIG>) -> BIG {
    let mut key: BIG = BIG::new_int(0);
    let q = BIG::new_ints(&rom::CURVE_ORDER);
    let ids:Vec<u8> =  (1..shares.len()+1).map(|x| x as u8).collect();

    for i in 0..shares.len() {
        let mut prod = BIG::new_big(&lagrange_coeff(&ids, (i+1) as isize));
        let mut tmp = BIG::mul(&prod, &shares[i]);
        prod = tmp.dmod(&q);
        
        key.add(&prod);
    }
    key.rmod(&q);

    return BIG::fromstring(key.tostring())
}

fn lagrange_coeff(indices: &[u8], i: isize) -> BIG {
    let mut prod = DBIG::new_scopy(&BIG::new_int(1));
    let q = BIG::new_big(&BIG::new_ints(&rom::CURVE_ORDER)); 
    
    for k in 0..indices.len() {
        let j:isize = indices[k].into();

        if i != j {
            let mut ij: BIG;
            let val = (j - i).abs();

            if i > j {
                ij = q.clone();
                ij.sub(&BIG::new_int(val));
            } else {
                ij = BIG::new_int(val);
            }
            ij.invmodp(&q);
            ij.imul(j as isize);

            prod = BIG::mul(&prod.dmod(&q), &ij);
        }
    } 

    let res = prod.dmod(&q);
    res
}